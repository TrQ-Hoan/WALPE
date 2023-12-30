package main

import (
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func expandPath(path string) (string, error) {
	// TODO: Add support for Linux
	// TODO: Add support for Windows share path
	var (
		err     error
		retpath string
	)
	winenv_regex := regexp.MustCompile(`^(%(\w+)%)(([\\/][a-z A-Z0-9_.-]+)*)$`)
	/* Regex example result:
	(INPUT) %Systemdrive%/Windows/System32/drivers
	[*] %Systemdrive%/Windows/System32/drivers   found at index 0
	[*] %Systemdrive%                            found at index 1
	[*] Systemdrive                              found at index 2
	[*] /Windows/System32/drivers                found at index 3
	[*] /drivers                                 found at index 4
	*/
	// Check if the path is a Windows environment variable
	matched_regex := winenv_regex.FindStringSubmatch(path)
	if len(matched_regex) > 0 {
		merged_regex := matched_regex[1] + matched_regex[3]
		env_str := ""
		if merged_regex != path {
			err = fmt.Errorf("path '%s' is not a valid windows environment variable path", path)
			return "", err
		}
		if strings.ToLower(matched_regex[2]) == "cwd" {
			env_str, err = os.Getwd()
		} else {
			env_str = os.Getenv(matched_regex[2])
		}
		if err != nil || env_str == "" {
			err = fmt.Errorf("error when getting environment variable '%s'", matched_regex[2])
			return "", err
		}
		retpath = filepath.Join(env_str, matched_regex[3])
		return retpath, nil
	}
	retpath, err = filepath.Abs(path)
	return retpath, err
}

func mkdir(dirPath string) error {
	fileInfo, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("error when creating directory: %v", err)
			}
			return nil
		}
		return fmt.Errorf("error when checking directory: %v", err)
	}

	if fileInfo.IsDir() {
		return nil
	}

	return fmt.Errorf("path is not a directory")
}

func rmfile(filepath string) error {
	if filepath == "" {
		return fmt.Errorf("path is empty")
	}
	run_fileout_stat, err := os.Stat(filepath)
	if err == nil {
		if run_fileout_stat.IsDir() {
			return fmt.Errorf("path '%s' is a directory", filepath)
		} else {
			err = os.Remove(filepath)
			if err != nil {
				return fmt.Errorf("error when removing file: %v", err)
			}
		}
	}
	return nil
}

func isFullPath(path string) (bool, error) {
	expath, err := expandPath(path)
	if err != nil {
		return false, err
	}
	if expath == path {
		return true, nil
	}
	return false, nil
}

func fileContainStr(str, filepath string) (bool, error) {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return false, err
	}

	isExist, err := regexp.Match(str, b)
	if err != nil {
		return false, err
	}
	return isExist, nil
}

func fileNotExisted(filepath string) error {
	if filepath == "" {
		return fmt.Errorf("path is empty")
	}
	_, err := os.Stat(filepath)
	if err == nil {
		return fmt.Errorf("file existed: %s", filepath)
	} else if os.IsNotExist(err) {
		return nil
	} else {
		return err
	}
}

func fileExisted(filepath string) error {
	if filepath == "" {
		return fmt.Errorf("path is empty")
	}
	_, err := os.Stat(filepath)
	return err
}

func copyFile(src, dst string) error {
	if src == "" {
		return fmt.Errorf("source path is empty")
	}
	if dst == "" {
		return fmt.Errorf("destination path is empty")
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}
	return nil
}

func checkFileAtTargetDir(targetDir string, fileName string) (string, error) {
	var (
		dstToolPath string
		requiredCp  bool
	)
	isFPath, err := isFullPath(fileName)
	if err != nil {
		return "", err
	}
	if !isFPath {
		fileName, err = expandPath(fileName)
		if err != nil {
			return "", err
		}
	} else {
		dstToolPath = fileName
	}
	if !strings.HasPrefix(fileName, targetDir) {
		dstToolPath = filepath.Join(targetDir, filepath.Base(fileName))
	}
	err = fileExisted(dstToolPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("file not found: %s", dstToolPath)
		}
		requiredCp = true
	} else {
		isSame, err := compareFiles(fileName, dstToolPath)
		if err != nil {
			return "", err
		}
		requiredCp = !isSame
	}
	if requiredCp {
		err = copyFile(fileName, dstToolPath)
		if err != nil {
			return "", err
		}
	}
	return dstToolPath, nil
}

func expCheckExist(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is empty")
	}
	path, err := expandPath(path)
	if err != nil {
		return "", err
	}
	err = fileExisted(path)
	if err != nil {
		return "", err
	}
	return path, nil
}

func calculateFileHash(file *os.File) (string, error) {
	hash := sha1.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashBytes := hash.Sum(nil)
	hashString := fmt.Sprintf("%x", hashBytes)

	return hashString, nil
}

func compareFiles(file1, file2 string) (bool, error) {
	f1, err := os.Open(file1)
	if err != nil {
		return false, err
	}
	defer f1.Close()

	f2, err := os.Open(file2)
	if err != nil {
		return false, err
	}
	defer f2.Close()

	hash1, err := calculateFileHash(f1)
	if err != nil {
		return false, err
	}

	hash2, err := calculateFileHash(f2)
	if err != nil {
		return false, err
	}

	if hash1 == hash2 {
		return true, nil
	} else {
		return false, nil
	}
}
