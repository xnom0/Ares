// Build
//
// go mod init ares
// go mod tidy
// CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ares
// CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ares.exe

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
	"golang.org/x/term"
)

const (
	exitSuccess = 0
	exitError   = 1
)

// ──────────────────────────────────────────────────────────────────────────────
// Progress writer
// ──────────────────────────────────────────────────────────────────────────────

type progressWriter struct {
	io.Writer
	bar *progressbar.ProgressBar
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.Writer.Write(p)
	if n > 0 {
		pw.bar.Add64(int64(n))
	}
	return
}

// ──────────────────────────────────────────────────────────────────────────────
// Password handling
// ──────────────────────────────────────────────────────────────────────────────

func readPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return pw, err
}

func readPasswordConfirm() ([]byte, error) {
	for {
		p1, err := readPassword("Private key password: ")
		if err != nil {
			return nil, err
		}
		p2, err := readPassword("Confirm password:        ")
		if err != nil {
			return nil, err
		}
		if bytes.Equal(p1, p2) {
			if len(p1) < 8 {
				fmt.Println("→ Password too short (minimum 8 characters)")
				continue
			}
			return p1, nil
		}
		fmt.Println("→ Passwords do not match.")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// X25519 key generation & loading
// ──────────────────────────────────────────────────────────────────────────────

func generateKeys() error {
	fmt.Println("Generating X25519 key pair...")
	pass, err := readPasswordConfirm()
	if err != nil {
		return err
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	block, err := x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", privDER, pass, x509.PEMCipherAES256)
	if err != nil {
		return err
	}

	if err := os.WriteFile("private.pem", pem.EncodeToMemory(block), 0600); err != nil {
		return err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return err
	}
	if err := os.WriteFile("public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		return err
	}

	fmt.Println("Keys created successfully:")
	fmt.Println(" - private.pem   (password protected)")
	fmt.Println(" -  public.pem   (share this with authorized users)\n")
	return nil
}

func loadPublicKey(path string) (*ecdh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read public key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM format in %s", path)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse public key: %w", err)
	}
	pub, ok := pubAny.(*ecdh.PublicKey)
	if !ok {
		return nil, errors.New("public key is not an X25519 key")
	}
	return pub, nil
}

func loadPrivateKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM format in %s", path)
	}

	var privDER []byte
	if x509.IsEncryptedPEMBlock(block) {
		pass, err := readPassword("Private key password: ")
		if err != nil {
			return nil, err
		}
		privDER, err = x509.DecryptPEMBlock(block, pass)
		if err != nil {
			return nil, errors.New("incorrect password or corrupted file")
		}
	} else {
		privDER = block.Bytes
	}

	privAny, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key: %w", err)
	}
	priv, ok := privAny.(*ecdh.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an X25519 key")
	}
	return priv, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Analyse de la taille totale (pour estimation du temps)
// ──────────────────────────────────────────────────────────────────────────────

func getTotalSize(path string) (int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("cannot access %s: %w", path, err)
	}
	if !fi.IsDir() {
		return fi.Size(), nil
	}

	var total int64
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// TAR — streaming vers un Writer
// ──────────────────────────────────────────────────────────────────────────────

func createTarToWriter(source string, w io.Writer) error {
	if _, err := os.Stat(source); err != nil {
		return fmt.Errorf("cannot access %s: %w", source, err)
	}

	tw := tar.NewWriter(w)

	fi, err := os.Stat(source)
	if err != nil {
		return err
	}
	baseName := filepath.Base(source)

	if !fi.IsDir() {
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = baseName
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(source)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(tw, f); err != nil {
			return fmt.Errorf("copy error during TAR creation: %w", err)
		}
	} else {
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = baseName + "/"
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		err = filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(source, p)
			if err != nil {
				return err
			}
			if rel == "." {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = filepath.Join(baseName, rel)
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if !d.IsDir() {
				f, err := os.Open(p)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := io.Copy(tw, f); err != nil {
					return fmt.Errorf("copy error for %s in TAR: %w", p, err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// LZMA2 decompression
// ──────────────────────────────────────────────────────────────────────────────

func decompressData(compressed []byte) ([]byte, error) {
	r, err := xz.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}

	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("[+] Decompression..."),
		progressbar.OptionSetWidth(50),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowIts(),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionThrottle(200*time.Millisecond),
		progressbar.OptionClearOnFinish(),
	)

	var out bytes.Buffer
	buf := make([]byte, 256*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
			bar.Add(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	bar.Finish()
	return out.Bytes(), nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Hybrid encryption / decryption
// ──────────────────────────────────────────────────────────────────────────────

func encryptData(plain []byte, pub *ecdh.PublicKey) ([]byte, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephPub := ephPriv.Public().(*ecdh.PublicKey)

	shared, err := ephPriv.ECDH(pub)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plain, nil)

	var out bytes.Buffer
	out.Write(ephPub.Bytes())
	out.Write(nonce)
	out.Write(ciphertext)
	return out.Bytes(), nil
}

func decryptData(enc []byte, priv *ecdh.PrivateKey) ([]byte, error) {
	r := bytes.NewReader(enc)

	ephPubBytes := make([]byte, 32)
	if _, err := io.ReadFull(r, ephPubBytes); err != nil {
		return nil, fmt.Errorf("[X] file too short (ephemeral key missing)")
	}

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("[X] invalid ephemeral public key: %w", err)
	}

	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, fmt.Errorf("[X] nonce missing or file corrupted")
	}

	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("[X] decryption failed (wrong key or corrupted file)")
	}
	return plaintext, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// TAR — extract
// ──────────────────────────────────────────────────────────────────────────────

func extractTarToDir(tarData []byte, destDir string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	tr := tar.NewReader(bytes.NewReader(tarData))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, hdr.Name)
		mode := os.FileMode(hdr.Mode)

		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, mode); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}

		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := io.Copy(f, tr); err != nil {
			return fmt.Errorf("[X] extraction error for %s: %w", hdr.Name, err)
		}

		if err := f.Chmod(mode); err != nil {
			return fmt.Errorf("[X] cannot set permissions on %s: %w", target, err)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// MAIN
// ──────────────────────────────────────────────────────────────────────────────

func main() {
	var exitCode = exitSuccess
	defer func() {
		os.Exit(exitCode)
	}()
	fmt.Println("Ares – Secure Archive - Copyright 2026")

	if len(os.Args) < 2 {
		fmt.Println("")
		fmt.Println("Usage : ares [function]")
		fmt.Println("")
		fmt.Println("Function Available :")
		fmt.Println("")
		fmt.Println("generate <Generate X25519 key pair>")
		fmt.Println("compress <input> <output> <level> [public.pem]")
		fmt.Println("decompress <file.ares> <output_dir> [private.pem]")
		fmt.Println("help <show help>")
		fmt.Println("")
		fmt.Println("Compression levels: 0 (very fast) → 9 (best compression, very slow)")
		fmt.Println("")
		return
	}

	switch os.Args[1] {
	case "help":
		fmt.Println("NAME")
		fmt.Println("    ares - secure archive tool (tar + lzma2 + X25519 encryption + AES-GCM)")
		fmt.Println("")
		fmt.Println("SYNOPSIS")
		fmt.Println("    ares generate")
		fmt.Println("    ares compress <file|folder> <archive.ares> <level> [path/to/public.pem]")
		fmt.Println("    ares decompress <archive.ares> <output_directory> [path/to/private.pem]")
		fmt.Println("")
		fmt.Println("DESCRIPTION")
		fmt.Println("    Ares creates and extracts strongly encrypted & compressed archives.")
		fmt.Println("    File extension: .ares")
		fmt.Println("")
		fmt.Println("COMMANDS")
		fmt.Println("    generate")
		fmt.Println("        Creates an X25519 key pair:")
		fmt.Println("          → private.pem  (AES-256 password protected)")
		fmt.Println("          → public.pem   (share this public key)")
		fmt.Println("")
		fmt.Println("    compress <input> <output> <level 0-9> [public.pem]")
		fmt.Println("        Creates a .ares archive from a file or folder")
		fmt.Println("        Steps performed:")
		fmt.Println("        1. Creates TAR archive (preserves folder structure)")
		fmt.Println("        2. Compresses with LZMA2 (level 0 = fastest → 9 = best ratio) → ON DISK")
		fmt.Println("        3. Encrypts using hybrid X25519 + AES-256-GCM")
		fmt.Println("        Automatically adds .ares extension if missing")
		fmt.Println("")
		fmt.Println("    decompress <file.ares> <output_folder> [private.pem]")
		fmt.Println("        Restores original files and folder structure")
		fmt.Println("        Requires file to end with .ares")
		fmt.Println("        Asks for private key password if the key is encrypted")
		fmt.Println("")
		fmt.Println("COMPRESSION LEVELS")
		fmt.Println("    0     very fast, low compression")
		fmt.Println("    6     good default balance")
		fmt.Println("    9     maximum compression, very slow & memory intensive")
		fmt.Println("")
		fmt.Println("EXAMPLES")
		fmt.Println("    ares generate")
		fmt.Println("    ares compress photos vacation-photos.ares 1")
		fmt.Println("    ares compress project ./secure-project.ares 9 public.pem")
		fmt.Println("    ares decompress secure-project.ares ./restored")

	case "generate":
		if err := generateKeys(); err != nil {
			fmt.Printf("Key generation failed: %v\n", err)
			exitCode = exitError
			return
		}

	case "compress":
		if len(os.Args) < 5 {
			fmt.Println("Usage: compress <input> <output> <level 0-9> [public.pem path]")
			exitCode = exitError
			return
		}

		inputPath := os.Args[2]
		outputPath := os.Args[3]

		if !strings.HasSuffix(strings.ToLower(outputPath), ".ares") {
			outputPath += ".ares"
			fmt.Printf("[+] Output archive: %s\n", outputPath)
		}

		level, err := strconv.Atoi(os.Args[4])
		if err != nil || level < 0 || level > 9 {
			fmt.Println("[X] Level must be an integer between 0 and 9")
			exitCode = exitError
			return
		}

		pubPath := "public.pem"
		if len(os.Args) >= 6 {
			pubPath = os.Args[5]
		}

		// Analyse de la taille
		fmt.Printf("[+] Analyzing input: %s\n", inputPath)
		totalSize, err := getTotalSize(inputPath)
		if err != nil {
			fmt.Printf("[X] Cannot compute size: %v\n", err)
			exitCode = exitError
			return
		}
		fmt.Printf("[+] Total input size: %d bytes (%.2f GB)\n", totalSize, float64(totalSize)/1024/1024/1024)

		// Determination du dossier de sortie
		outputDir := filepath.Dir(outputPath)
		if outputDir == "." || outputDir == "" {
			outputDir = "."
		}

		// Creation du fichier temporaire dans le dossier de destination
		tmpFile, err := os.CreateTemp(outputDir, "ares-compress-*.tmp")
		if err != nil {
			fmt.Printf("[X] Cannot create temporary file in %s: %v\n", outputDir, err)
			exitCode = exitError
			return
		}
		compressedPath := tmpFile.Name()
		fmt.Printf("[+] Temporary file: %s\n", compressedPath)

		// Gestion propre des interruptions (Ctrl+C)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigChan
			fmt.Println("\n[!] Compression interrupted by user (Ctrl+C)")
			cancel() // signale l'arrêt
			os.Remove(compressedPath)
		}()

		// Configuration LZMA2
		cfg := xz.WriterConfig{DictCap: 8 << 20}
		switch level {
			case 0: cfg.DictCap = 64 << 10
			case 1, 2: cfg.DictCap = 1 << 20
			case 3, 4: cfg.DictCap = 4 << 20
			case 7: cfg.DictCap = 16 << 20
			case 8: cfg.DictCap = 32 << 20
			case 9: cfg.DictCap = 64 << 20
		}

		xzw, err := cfg.NewWriter(tmpFile)
		if err != nil {
			fmt.Printf("[X] Compressor init failed: %v\n", err)
			exitCode = exitError
			return
		}

		bar := progressbar.NewOptions64(totalSize,
						progressbar.OptionSetDescription("[+] Compression"),
						progressbar.OptionSetWidth(60),
						progressbar.OptionShowBytes(true),
						progressbar.OptionShowCount(),
						progressbar.OptionSetPredictTime(true),
						progressbar.OptionThrottle(300*time.Millisecond),
						progressbar.OptionClearOnFinish(),
		)

		pw := &progressWriter{Writer: xzw, bar: bar}

		fmt.Println("[+] Compressing... (Ctrl+C to cancel)")

		// Compression avec possibilite d'interruption
		done := make(chan error, 1)
		go func() {
			done <- createTarToWriter(inputPath, pw)
		}()

		var compressErr error
		select {
			case compressErr = <-done:
				// compression terminee normalement
			case <-ctx.Done():
				compressErr = errors.New("interrupted")
		}

		// Fermeture propre
		if err := xzw.Close(); err != nil && compressErr == nil {
			compressErr = err
		}
		tmpFile.Close()

		bar.Finish()

		if compressErr != nil {
			if compressErr.Error() == "interrupted" {
				fmt.Println("[!] Compression cancelled.")
			} else {
				fmt.Printf("[X] Compression failed: %v\n", compressErr)
			}
			os.Remove(compressedPath) // nettoyage du fichier temporaire
			exitCode = exitError
			return
		}

		// Lecture du fichier compressé
		compressed, err := os.ReadFile(compressedPath)
		if err != nil {
			fmt.Printf("[X] Cannot read compressed data: %v\n", err)
			os.Remove(compressedPath)
			exitCode = exitError
			return
		}
		fmt.Printf("[+] Compressed size: %d bytes (%.2f GB)\n", len(compressed), float64(len(compressed))/1024/1024/1024)

		// Encryption
		pub, err := loadPublicKey(pubPath)
		if err != nil {
			fmt.Printf("[X] Public key error: %v\n", err)
			os.Remove(compressedPath)
			exitCode = exitError
			return
		}

		fmt.Print("[+] Encrypting (X25519 + AES-GCM)... ")
		protected, err := encryptData(compressed, pub)
			if err != nil {
				fmt.Printf("[X] failed: %v\n", err)
				os.Remove(compressedPath)
				exitCode = exitError
				return
			}
			fmt.Println("OK")

			if err := os.WriteFile(outputPath, protected, 0644); err != nil {
				fmt.Printf("[X] Write error: %v\n", err)
				os.Remove(compressedPath)
				exitCode = exitError
				return
			}

			// Nettoyage
			os.Remove(compressedPath)
			fmt.Printf("[+] Encrypted archive created successfully: %s\n", outputPath)


	case "decompress":
		if len(os.Args) < 4 {
			fmt.Println("Usage: decompress <file.ares> <output_dir> [private.pem path]")
			exitCode = exitError
			return
		}

		inputPath := os.Args[2]
		if !strings.HasSuffix(strings.ToLower(inputPath), ".ares") {
			fmt.Println(" [X] Error: input file must end with .ares")
			fmt.Printf("[+] Provided file: %s\n", inputPath)
			exitCode = exitError
			return
		}

		outputDir := os.Args[3]

		privPath := "private.pem"
		if len(os.Args) >= 5 {
			privPath = os.Args[4]
		}

		fmt.Printf("[+] Reading file: %s\n", inputPath)
		encData, err := os.ReadFile(inputPath)
		if err != nil {
			fmt.Printf("[X] Cannot read file: %v\n", err)
			exitCode = exitError
			return
		}

		priv, err := loadPrivateKey(privPath)
		if err != nil {
			fmt.Printf("[X] Private key error: %v\n", err)
			exitCode = exitError
			return
		}

		fmt.Print("[+] Decrypting (X25519 + AES-GCM)... ")
		compressed, err := decryptData(encData, priv)
		if err != nil {
			fmt.Printf("[X] failed: %v\n", err)
			exitCode = exitError
			return
		}
		fmt.Println("OK")

		fmt.Println("[+] Decompression...")
		tarData, err := decompressData(compressed)
		if err != nil {
			fmt.Printf("[X] Decompression failed: %v\n", err)
			exitCode = exitError
			return
		}

		fmt.Printf("[+] Extracting to: %s\n", outputDir)
		if err := extractTarToDir(tarData, outputDir); err != nil {
			fmt.Printf("[X] Extraction failed: %v\n", err)
			exitCode = exitError
			return
		}
		fmt.Println("Extraction completed successfully!")

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		fmt.Println("Use: generate, compress or decompress")
		exitCode = exitError
	}
}

