package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
	"gopkg.in/yaml.v2"
)

func expandPath(path string) (string, error) {
	// TODO: Add support for Linux
	// TODO: Add support for Windows share path
	var err error
	var retpath string
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

func isFullPath(path string) bool {
	expath, err := expandPath(path)
	if err != nil {
		log.Fatalln(color.RedString(" [x]"), "(IsFullPath) Error when expanding path:", err)
	}
	if expath == path {
		return true
	}
	return false
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

type AttackInfo struct {
	AttackName          string `yaml:"att_name"`
	AttackCommand       string `yaml:"att_cmd"`
	CredentialCommand   string `yaml:"cred_cmd"`
	CredentialOutputDir string `yaml:"cred_dir"`
	CredentialFilePre   string `yaml:"cred_file_pre"`
	CredentialFileAft   string `yaml:"cred_file_aft"`
}

/*
input:

	fileYamlPath: path to the YAML file
	attackName: name of the attack

output:

	run_command: command to run
	run_fileout: file to output
*/
func parseYAML(fileYamlPath string, attkName string, isBefore bool) (string, string, error) {
	var err error
	if attkName == "" {
		err = fmt.Errorf("attack name is empty")
		return "", "", err
	}
	// Open file YAML
	yamlfile, err := os.ReadFile(fileYamlPath)
	if err != nil {
		err = fmt.Errorf("error when opening YAML file: %v", err)
		return "", "", err
	}

	// Initialize a variable to unmarshal data into
	var attacks []AttackInfo

	// Read and unmarshal data from the YAML file into the config variable
	err = yaml.Unmarshal(yamlfile, &attacks)
	if err != nil {
		err = fmt.Errorf("error when reading and unmarshalling YAML data: %v", err)
		return "", "", err
	}

	for _, item := range attacks {
		if item.AttackName == attkName {
			if item.CredentialOutputDir != "" {
				path, err := expandPath(item.CredentialOutputDir)
				if err != nil {
					err = fmt.Errorf("error when expanding path: %v", err)
					return "", "", err
				}
				err = mkdir(path)
				if err != nil {
					err = fmt.Errorf("error when creating directory: %v", err)
					return "", "", err
				}
				var run_fileout string
				if isBefore {
					if isFullPath(item.CredentialFilePre) {
						run_fileout = item.CredentialFilePre
					} else {
						run_fileout = filepath.Join(path, item.CredentialFilePre)
					}
				} else {
					if isFullPath(item.CredentialFileAft) {
						run_fileout = item.CredentialFileAft
					} else {
						run_fileout = filepath.Join(path, item.CredentialFileAft)
					}
				}
				return item.CredentialCommand, run_fileout, nil
			}
			return "", "", err
		}
	}
	err = fmt.Errorf("not found '%s' in file '%s'", attkName, fileYamlPath)
	return "", "", err
}

func executeCommand(command string, fileout string) (string, string, error) {
	// Create a cmd object to execute the command
	args := strings.Split(command, " ")
	cmd := exec.Command(args[0], args[1:]...)
	// fmt.Println(cmd.Args) // DEBUG
	// Create pipes for stderr
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", fmt.Errorf("error creating stderr pipe: %s", err.Error())
	}

	// Create an empty string for stdout
	var stdout string

	if fileout != "" {
		// Open the output file
		file, err := os.Create(fileout)
		if err != nil {
			return "", "", fmt.Errorf("error creating output file: %s", err.Error())
		}
		defer file.Close()

		// Assign the file as the stdout writer
		cmd.Stdout = file
		stdout = ""

		// Start the command
		err = cmd.Start()
		if err != nil {
			return "", "", fmt.Errorf("error starting command: %s", err.Error())
		}
	} else {
		// Create a pipe for stdout
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return "", "", fmt.Errorf("error creating stdout pipe: %s", err.Error())
		}

		// Start the command
		err = cmd.Start()
		if err != nil {
			return "", "", fmt.Errorf("error starting command: %s", err.Error())
		}

		// Read stdout
		stdout, err = readPipe(stdoutPipe)
		if err != nil {
			return "", "", fmt.Errorf("error reading stdout: %s", err.Error())
		}

	}

	// Read stderr
	stderr, err := readPipe(stderrPipe)
	if err != nil {
		return "", "", fmt.Errorf("error reading stderr: %s", err.Error())
	}

	// Wait for the command to finish
	err = cmd.Wait()
	if err != nil {
		return "", stderr, fmt.Errorf("command execution error: %s", err.Error())
	}

	return stdout, stderr, nil
}

func readPipe(pipeStdoutStderr io.Reader) (string, error) {
	data, err := io.ReadAll(pipeStdoutStderr)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func main() {
	// Initialize log
	log.SetOutput(colorable.NewColorableStdout())
	log.SetFlags(0)
	// Parse flags
	if len(os.Args) < 3 || len(os.Args) > 4 {
		log.Fatalln(color.RedString(" [x]"), "Usage: checkpriv.exe <.yaml file> <attack_name> [-b]")
	}
	configFile := os.Args[1]
	attackName := os.Args[2]
	isBefore := false
	if len(os.Args) == 4 {
		if os.Args[3] == "-b" {
			isBefore = true
		} else {
			error := fmt.Errorf("unknown flag '%s'", os.Args[3])
			log.Fatalln(color.RedString(" [x]"), error)
		}
	}

	run_command, run_fileout, err := parseYAML(configFile, attackName, isBefore)
	if err != nil {
		log.Fatalln(color.RedString(" [x]"), "Error when parsing YAML:", err)
	}
	// Check run_fileout exists
	if run_fileout != "" {
		run_fileout_stat, err := os.Stat(run_fileout)
		if err == nil {
			if run_fileout_stat.IsDir() {
				log.Fatalln(color.RedString(" [x]"), "Path", run_fileout, "is a directory")
			} else {
				err = os.Remove(run_fileout)
				if err != nil {
					log.Fatalln(color.RedString(" [x]"), "Error when removing file:", err)
				}
			}
		}
	}
	sout, serr, err := executeCommand(run_command, run_fileout)
	if err != nil {
		log.Println(color.RedString(" [x]"), "Error when executing command:", err)
	}
	if sout != "" {
		fmt.Println(" [+] STDOUT:", sout)
	}
	if serr != "" {
		fmt.Println(" [-] STDERR:", serr)
	}
}
