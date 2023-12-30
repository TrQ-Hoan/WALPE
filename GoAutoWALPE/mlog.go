package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/fatih/color"
	gf "github.com/iexpurgator/gom/lib/go_fmt"
)

func writeLog(loglevel string, a string) {
	la := strings.Split(a, "\n")
	for _, l := range la {
		log.Printf("| %10s | %s\n", loglevel, strings.TrimSpace(l))
	}
}

func conHiDBG(a ...interface{}) (n int, err error) {
	sa := fmt.Sprint(a...)
	writeLog("DEBUG", sa)
	return gf.Console.Println(color.HiYellowString(" >>>") + " " + sa)
}

func logInfo(a ...interface{}) (n int, err error) {
	sa := fmt.Sprint(a...)
	writeLog("INFO", sa)
	return gf.Console.Println(color.BlueString(" [*]") + " " + sa)
}

func logNoti(a ...interface{}) (n int, err error) {
	sa := fmt.Sprint(a...)
	writeLog("NOTI", sa)
	return gf.Console.Println(color.HiMagentaString(" [#]") + " " + sa)
}

func logNoti2(a ...interface{}) (n int, err error) {
	sa := fmt.Sprint(a...)
	writeLog("NOTI", sa)
	return gf.Console.Println(color.BlueString(" [#]") + " " + sa)
}

func logErro(a ...interface{}) (n int, err error) {
	if err == nil {
		return 0, nil
	}
	sa := fmt.Sprint(a...)
	writeLog("ERRO", sa)
	return gf.Console.Println(color.RedString(" [x]") + " " + sa)
}

// func conwarn(a ...interface{}) (n int, err error) {
// 	sa := fmt.Sprint(a...)
// 	return gf.Console.Println(color.YellowString(" [-]") + " " + sa)
// }

func logOk(a ...interface{}) (n int, err error) {
	sa := fmt.Sprint(a...)
	writeLog("OK", sa)
	return gf.Console.Println(color.GreenString(" [+]") + " " + sa)
}

func logInfo_dbg(a ...interface{}) (n int, err error) {
	sa := fmt.Sprint(a...)
	writeLog("LOG-INFO", sa)
	if !verbose {
		return 0, nil
	}
	return gf.Console.Println(color.HiMagentaString(" [ ]") + " " + sa)
}

func logWarn_dbg(level int, msg string, a ...interface{}) (n int, err error) {
	level = level % 3
	sa := fmt.Sprint(a...)
	level_str := []string{"LOG-STDOUT", "LOG-STDERR", "LOG-ERROR"}
	writeLog(level_str[level], sa)
	if sa == "" {
		return 0, nil
	}
	if !verbose {
		return 0, nil
	}
	if level == 1 {
		sa = color.HiRedString(sa)
	}
	level_code := []string{" [!]", " [!]", " [?]"}
	return gf.Console.Println(color.YellowString(level_code[level]), msg, sa)
}

func logRaise(msg string, err error) {
	if err == nil {
		return
	}
	writeLog("EXCEPTION", fmt.Sprintf("%s %s", msg, err))
	gf.Console.Println(color.HiRedString(" [x]"), msg, err)
	os.Exit(1)
}

func logSuccess(strOut string) (n int, err error) {
	sa := color.GreenString(" [+] Successful")
	// if strOut != "" {
	if strOut != "" {
		writeLog("LOG-STDOUT", strOut)
		if len(strOut) < 1234 || verbose {
			sa = color.GreenString(" [+] Stdout: ") + strOut + "\n" + sa
		}
	}
	writeLog("STATUS", "Successful")
	return gf.Console.Println(sa)
}

func logFailed(strOut string, strErr string, inErr string, retry bool) (n int, err error) {
	logWarn_dbg(0, "Stdout:", strOut)
	logWarn_dbg(1, "Stderr:", strings.Trim(strErr, "\r\n"))
	logWarn_dbg(2, "(ERROR)", inErr)
	writeLog("STATUS", "Failed")
	sa := color.YellowString(" [x] Failed")
	if retry {
		sa = sa + " - retrying..."
		writeLog("INFO", "Start trying again")
	}
	return gf.Console.Println(sa)
}

func logWriteRowFmt(format string, a ...interface{}) (n int, err error) {
	sa := fmt.Sprintf(format, a...)
	writeLog("TABLE", sa)
	return gf.Console.Println(color.HiMagentaString(" [~]"), sa)
}

func logWriteTitle(a ...interface{}) (n int, err error) {
	sa := fmt.Sprint(a...)
	writeLog("SESSION", sa)
	return gf.Console.Println(color.CyanString(" [@]"), sa)
}

func logWriteln(a ...interface{}) (n int, err error) {
	sa := fmt.Sprint(a...)
	writeLog("MESSAGE", sa)
	return gf.Console.Println(color.MagentaString(" [=]"), sa)
}

func logWritefmt(format string, a ...interface{}) (n int, err error) {
	sa := fmt.Sprintf(format, a...)
	writeLog("F-MESSAGE", sa)
	return gf.Console.Println(color.HiYellowString(" [=]"), sa)
}

func contentFile2Log(msg string, filename string) {
	writeLog("INFO", fmt.Sprint(msg, filename))
	f, err := os.Open(filename)
	if err != nil {
		writeLog("FILE-ERR", fmt.Sprint("Error when opening file:", err))
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		writeLog("FILE-ERR", fmt.Sprint("Error when getting file info:", err))
		return
	}
	if stat.Size() == 0 {
		writeLog("FILE-MSG", "File is empty")
		return
	} else if stat.Size() > 8*1024 {
		writeLog("FILE-MSG", "File is too large")
		return
	}
	b, err := os.ReadFile(filename)
	if err != nil {
		writeLog("FILE-ERR", fmt.Sprint("Error when reading file:", err))
		return
	}
	writeLog("FILE", string(b))
}
