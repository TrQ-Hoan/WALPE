package main

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

func readPipe(pipeStdoutStderr io.Reader) (string, error) {
	data, err := io.ReadAll(pipeStdoutStderr)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func splitCommandLine(input string) []string {
	var (
		parts       []string
		currentPart strings.Builder
	)

	insideQuotes := false
	for _, char := range input {
		switch char {
		case ' ':
			if !insideQuotes {
				parts = append(parts, currentPart.String())
				currentPart.Reset()
				continue
			}
		case '"':
			insideQuotes = !insideQuotes
		}
		currentPart.WriteRune(char)
	}

	if currentPart.Len() > 0 {
		parts = append(parts, currentPart.String())
	}

	return parts
}

func executeCommand(command []string) (string, string, error) {
	if len(command) == 0 {
		return "", "", fmt.Errorf("command is empty")
	}
	// Create a cmd object to execute the command
	var cmd *exec.Cmd
	if len(command) == 1 {
		cmd = exec.Command(command[0])
	} else {
		cmd = exec.Command(command[0], command[1:]...)
	}
	// fmt.Println(cmd.Args)

	// Create pipes for stdout and stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", fmt.Errorf("error creating stdout pipe: %s", err.Error())
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", fmt.Errorf("error creating stderr pipe: %s", err.Error())
	}

	// Start the command
	err = cmd.Start()
	if err != nil {
		return "", "", fmt.Errorf("error starting command: %s", err.Error())
	}

	// Read stdout and stderr
	stdout, err := readPipe(stdoutPipe)
	if err != nil {
		return "", "", fmt.Errorf("error reading stdout: %s", err.Error())
	}

	stderr, err := readPipe(stderrPipe)
	if err != nil {
		return "", "", fmt.Errorf("error reading stderr: %s", err.Error())
	}

	// Wait for the command to finish
	err = cmd.Wait()
	if err != nil {
		return stdout, stderr, fmt.Errorf("command execution error: %s", err.Error())
	}

	return stdout, stderr, nil
}
