package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
)

var (
	verbose       bool
	hdsd          bool
	tmpYamlPath   string
	hasRemote     bool
	resultAttkMap map[string]bool
)

type ConnectionStatus struct {
	StartTime time.Time
	Timeout   time.Duration
	Connected bool
	Closed    bool
	Status    int
}

func localAttack(config AttackInfo, toolPath string) {
	var (
		strOut string
		strErr string
		err    error
	)
	/* -------------------- Before attack -------------------- */
	logNoti(config.AttackName, " - check privilege before attack")
	checkcre_cmd := []string{toolPath, tmpYamlPath, config.AttackName, "-b"}
	logInfo_dbg(config.AttackName, " - check credential command: ", checkcre_cmd)
	strOut, strErr, err = executeCommand(checkcre_cmd)
	if err != nil {
		logFailed(strOut, strErr, err.Error(), false)
	} else {
		logSuccess(strOut)
		contentFile2Log("File credential: ", config.CredentialFilePre)
	}

	/* -------------------- Attack -------------------- */
	logNoti(config.AttackName, " - attacking...")
	attack_cmd := splitCommandLine(config.AttackCommand)
	attack_cmd = append(attack_cmd, toolPath, tmpYamlPath, config.AttackName)
	logInfo_dbg(config.AttackName, " - attack command: ", attack_cmd)
	try_count := 0
	for try_count < 3 {
		try_count++
		strOut, strErr, err = executeCommand(attack_cmd)
		if err != nil {
			resultAttkMap[config.AttackName] = false
			logFailed(strOut, strErr, err.Error(), try_count < 3)
			if strings.Contains(err.Error(), "command execution error: exit status 5") {
				continue
			}
			if strings.Contains(err.Error(), "cannot run executable found relative to current directory") {
				logErro("Error when executing command:", err)
				break
			}
		} else {
			resultAttkMap[config.AttackName] = true
			logSuccess(strOut)
			contentFile2Log("File credential: ", config.CredentialFileAft)
			break
		}
	}
}

func remoteAttack(config AttackInfo, toolPath string) {
	var (
		strOut string
		err    error
		// stderr string
		optionCommand string
	)
	command := []string{}
	msg_infor := []string{"check privilege before attack", "attacking..."}
	msg_verbose := []string{"check credential command: ", "attack command: "}
	checkErr_cmd := "echo %ERRORLEVEL%"
	exit_cmd := "exit"
	/* -------------------- init remote attack -------------------- */
	checkcre_cmd := strings.Join([]string{toolPath, tmpYamlPath, config.AttackName, "-b"}, " ")
	attack_cmd := strings.Join([]string{config.AttackCommand, optionCommand, toolPath, tmpYamlPath, config.AttackName}, " ")
	command = append(command, checkcre_cmd, checkErr_cmd, attack_cmd, checkErr_cmd, exit_cmd)
	/* -------------------- remote attack -------------------- */
	logNoti(config.AttackName, " - remote attack")
	port_listen := ":" + config.RemoteAttack.RemoteConnPort
	listener, err := net.Listen("tcp", port_listen)
	if err != nil {
		logErro("Error when listening:", err)
		return
	}
	defer listener.Close()

	connStatus := ConnectionStatus{
		StartTime: time.Now(),
		Timeout:   10 * time.Second,
		Connected: false,
		Closed:    false,
	}

	go func() {
		var strOut, strErr string
		var err error
		time.Sleep(1 * time.Second)
		strOut, strErr, err = executeCommand(strings.Fields(config.RemoteAttack.RemoteConnCommand))
		if err != nil {
			if strings.HasSuffix(err.Error(), "exit status 7") {
				if !connStatus.Closed {
					listener.Close()
					connStatus.Closed = true
				}
			}
			logWarn_dbg(2, "Error when executing command (remcon):", err)
			logWarn_dbg(0, "Stdout (remcon):", strOut)
			logWarn_dbg(1, "Stderr (remcon):", color.HiRedString(strings.Trim(strErr, "\r\n")))
		} else if strOut != "" && verbose {
			logOk("Stdout (remcon): ", strOut)
		}
	}()

	go func() {
		if connStatus.Closed {
			return
		}
		logNoti2("Waiting 10s for connection")
		for time.Since(connStatus.StartTime) < connStatus.Timeout {
			if connStatus.Closed {
				logNoti2("Listener has closed !!!")
				break
			}
		}
		if !connStatus.Connected && !connStatus.Closed {
			logErro("No connection created, close listener !!!")
			listener.Close()
			connStatus.Closed = true
		}
	}()

	// accept connection
	conn, err := listener.Accept()
	if err != nil {
		logErro("Error when accepting:", err)
		return
	}
	defer conn.Close()
	connStatus.Connected = true
	logNoti2("New connection from: ", conn.RemoteAddr())

	idx := 0
	retry := 0
	var (
		delay    int
		filename string
	)
	delay = 2 + config.RemoteAttack.RemoteExcComDelay
	for {
		// logWriteln(color.HiGreenString(" ==="), "delay (s):", delay)
		time.Sleep(time.Duration(delay) * time.Second)
		buffer, err := readUntilNull(conn)
		if err != nil {
			if err.Error() != "EOF" {
				logErro("Error when reading:", err)
			}
			break
		}
		if idx > len(command)-1 {
			break
		}
		if idx > 0 {
			full_output := string(buffer)
			len_command := len(command[idx-1])
			index := strings.Index(string(buffer), command[idx-1])
			full_output = strings.TrimSpace(full_output[index+len_command:])
			output_lines := strings.Split(full_output, "\r\n")
			// logWriteln(strings.Join(output_lines, " ; "))
			output_num_line := len(output_lines)
			full_output = strings.Join(output_lines[:output_num_line-1], "\n")
			// logWriteln("FullOut:", full_output)
			output := output_lines[0]
			if idx%2 == 1 {
				logNoti(config.AttackName, " - ", msg_infor[idx/2])
				logInfo_dbg(config.AttackName, " - ", msg_verbose[idx/2], command[idx-1])
				strOut = full_output
				delay = 3 + idx/2 + config.RemoteAttack.RemoteExcComDelay
			} else {
				if output != "0" {
					resultAttkMap[config.AttackName] = false
					if idx == 4 && strOut != "Access is denied." && output == "5" && retry < 3 {
						idx -= 2
						retry += 1
					}
					logFailed("", strOut, output, retry != 0 && retry <= 3)
					if output == "9009" {
						// MSG_DIR_BAD_COMMAND_OR_FILE
						return
					} else if output == "3" {
						// ERROR_PATH_NOT_FOUND
						return
					}
				} else {
					resultAttkMap[config.AttackName] = true
					logSuccess(strOut)
					if idx == len(command)-1 {
						filename = config.CredentialFileAft
					} else {
						filename = config.CredentialFilePre
					}
					contentFile2Log("File credential: ", filename)
				}
				delay = 1 + config.RemoteAttack.RemoteExcComDelay
			}
		} else {
			delay = 1 + config.RemoteAttack.RemoteExcComDelay
		}

		// gửi lệnh đi
		_, err = conn.Write([]byte(command[idx] + "\n"))
		if err != nil {
			logErro("Error when writing:", err)
			break
		}
		err = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err != nil {
			logErro("Error when setting write deadline:", err)
			break
		}
		idx += 1
		if idx >= len(command) {
			delay = config.RemoteAttack.RemoteExcComDelay
		}
	}
	logNoti2("Connection closed: ", conn.RemoteAddr())
}

func main() {
	var (
		err     error
		tmplist map[string]bool
	)
	// Get log file name
	logFileName := func() string {
		filename := filepath.Base(os.Args[0])
		filenameWithoutExt := strings.TrimSuffix(filename, filepath.Ext(filename))
		logFileName := fmt.Sprintf("%s_%s.log", filenameWithoutExt, time.Now().Format("20060102_150405"))
		return logFileName
	}()

	// Parse flags
	configFile := flag.String("config", "config.yaml", "Path to the YAML config file")
	toolCheck := flag.String("tool", "checkpriv.exe", "Tool check privilege with YAML config file")
	toolNc := flag.String("nc", "nc.exe", "Tool nc for remote attack")
	toolWalpe := flag.String("walpe", "SharpWALPE.exe", "Tool WALPE - Windows Active Local Privilege Escalation")
	flag.StringVar(&logFileName, "log", logFileName, "Log file name")
	flag.BoolVar(&verbose, "V", false, "Verbose mode")
	flag.BoolVar(&hdsd, "hdsd", false, "Manual (vietnamese only)")
	flag.Parse()

	if hdsd {
		HDSD()
		os.Exit(0)
	}

	// Initialize log
	file, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	logRaise("Error when opening log file:", err)
	defer file.Close()
	log.SetOutput(colorable.NewNonColorable(file))
	// Initialize temp set
	tmplist = make(map[string]bool)
	// Check tool checkpriv

	pathToolCheck, err := expCheckExist(*toolCheck)
	logRaise("Error when expanding path of tool (checkpriv):", err)
	// Check tool walpe
	pathToolWalpe, err := expCheckExist(*toolWalpe)
	logRaise("Error when expanding path of tool (walpe):", err)
	// Check tool nc
	pathToolNc, err := expCheckExist(*toolNc)
	logRaise("Error when expanding path of tool (nc):", err)

	publicPathNc, err := checkFileAtTargetDir("C:\\Users\\Public", pathToolNc)
	logRaise("Error when checking tool:", err)
	if publicPathNc != pathToolNc {
		tmplist[publicPathNc] = true
	}

	// configPath, err := expandPath(*configFile)
	tmpYaml := "C:\\Users\\Public\\tmp.yaml"
	tmpYamlPath, err = expandPath(tmpYaml)
	logRaise("Error when expanding path of config:", err)
	tmplist[tmpYamlPath] = true

	// Run
	attackMap, err := parseYAML(*configFile, tmpYaml, verbose)
	logRaise("Error when parsing YAML:", err)
	logWriteln(color.MagentaString("====================================="))

	resultAttkMap = make(map[string]bool)
	for _, config := range attackMap {
		logWriteTitle(config.AttackName)
		/* -------------------- check remote attack -------------------- */
		if config.RemoteAttack.RemoteConnPort != "" {
			// Check tool nc
			remotePathNc, err := checkFileAtTargetDir(config.CredentialOutputDir, pathToolNc)
			logRaise("Error when checking tool:", err)
			if remotePathNc != pathToolNc {
				tmplist[remotePathNc] = true
			}
			// Check tool WALPE
			remoteToolPathWalpe, err := checkFileAtTargetDir(config.CredentialOutputDir, pathToolWalpe)
			logRaise("Error when checking tool:", err)
			if remoteToolPathWalpe != pathToolWalpe {
				tmplist[remoteToolPathWalpe] = true
			}
			// Check tool privilege
			remoteToolPath, err := checkFileAtTargetDir(config.CredentialOutputDir, pathToolCheck)
			logRaise("Error when checking tool:", err)
			if remoteToolPath != pathToolCheck {
				tmplist[remoteToolPath] = true
			}
			// remote attack
			hasRemote = true
			remoteAttack(config, remoteToolPath)
		} else {
			localAttack(config, pathToolCheck)
		}
	}

	// Print out the result
	if hasRemote {
		time.Sleep(1 * time.Second)
	}
	logWriteln(color.MagentaString("====================================="))
	logWriteRowFmt("%-10s %s", "ATTACK", "RESULT")
	for attack, result := range resultAttkMap {
		if result {
			// befFound, err := fileContainStr(" S-1-5-21-*", attackMap[attack].CredentialFilePre)
			befFound, err := fileContainStr(" S-1-5-18", attackMap[attack].CredentialFilePre)
			logErro("Error when checking credential file (pre):", err)
			aftFound, err := fileContainStr(" S-1-5-18", attackMap[attack].CredentialFileAft)
			logErro("Error when checking credential file (aft):", err)
			// logWriteln(!befFound, aftFound)
			result = !befFound && aftFound
		}
		logWriteRowFmt("%-10s %s", attack, ternary(result, color.HiGreenString("[V] Success"), color.YellowString("[x] Failed")))
	}
	// Delete tmp file
	for tmp := range tmplist {
		err = os.Remove(tmp)
		if err != nil {
			logErro("Error when deleting tmp file:", err)
		}
	}
}
