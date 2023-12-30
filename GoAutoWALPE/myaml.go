package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

type RemAttInfo struct {
	RemoteConnPort    string `yaml:"remcon_port"`
	RemoteConnCommand string `yaml:"remcon_cmd"`
	RemoteExcComDelay int    `yaml:"remcon_delay,omitempty"`
	// RemoteConnIp      string `yaml:"remcon_ip"`
	// RemoteConnType    string `yaml:"remcon_type"`
}

type AttackInfo struct {
	AttackName          string     `yaml:"att_name"`
	AttackCommand       string     `yaml:"att_cmd"`
	CredentialCommand   string     `yaml:"cred_cmd"`
	CredentialOutputDir string     `yaml:"cred_dir"`
	CredentialFilePre   string     `yaml:"cred_file_pre"`
	CredentialFileAft   string     `yaml:"cred_file_aft"`
	RemoteAttack        RemAttInfo `yaml:"rem_att,omitempty"`
}

func parseYAML(fileYamlPath string, outYamlTmpPath string, callerVerbose bool) (map[string]AttackInfo, error) {
	var err error
	// Open file YAML
	yamlfile, err := os.ReadFile(fileYamlPath)
	if err != nil {
		err = fmt.Errorf("error when opening YAML file: %v", err)
		return nil, err
	}

	// Initialize a variable to unmarshal data into
	var attacks []AttackInfo

	// Read and unmarshal data from the YAML file into the config variable
	err = yaml.Unmarshal(yamlfile, &attacks)
	if err != nil {
		err = fmt.Errorf("error when reading and unmarshalling YAML data: %v", err)
		return nil, err
	}

	logInfo("Number of attack(s): ", len(attacks))

	uniqueIDs := make(map[string]AttackInfo)
	for _, item := range attacks {
		if uniqueIDs[item.AttackName] != (AttackInfo{}) {
			err = fmt.Errorf("attack name '%s' is duplicated", item.AttackName)
			return nil, err
		} else {
			var outDirPath string
			// var rematt RemAttInfo
			if item.CredentialOutputDir != "" {
				outDirPath, err = expandPath(item.CredentialOutputDir)
				if err == nil {
					logOk(item.AttackName)
				} else {
					err = fmt.Errorf("error when expanding path: %v", err)
					return nil, err
				}
				err = mkdir(outDirPath)
				if err != nil {
					err = fmt.Errorf("error when creating directory: %v", err)
					return nil, err
				}
			}
			pathFilePre := filepath.Join(outDirPath, item.CredentialFilePre)
			pathFileAft := filepath.Join(outDirPath, item.CredentialFileAft)
			rmfile(pathFilePre)
			rmfile(pathFileAft)
			// if callerVerbose {
			if strings.Contains(item.AttackCommand, "--command") {
				item.AttackCommand = strings.Replace(item.AttackCommand, "--command", "--verbose --command", 1)
			} else if strings.Contains(item.AttackCommand, "-c") {
				item.AttackCommand = strings.Replace(item.AttackCommand, " -c", " -v -c", 1)
			}
			// }

			uniqueIDs[item.AttackName] = AttackInfo{
				AttackName:          item.AttackName,
				AttackCommand:       item.AttackCommand,
				CredentialCommand:   item.CredentialCommand,
				CredentialOutputDir: outDirPath,
				CredentialFilePre:   pathFilePre,
				CredentialFileAft:   pathFileAft,
				RemoteAttack:        item.RemoteAttack,
			}
		}
	}
	if outYamlTmpPath != "" {
		rmfile(outYamlTmpPath)
		yamlfileout, err := os.Create(outYamlTmpPath)
		if err != nil {
			err = fmt.Errorf("error when creating YAML file: %v", err)
			return nil, err
		}
		defer yamlfileout.Close()

		yamlenc := yaml.NewEncoder(yamlfileout)
		var arr []AttackInfo
		for _, v := range uniqueIDs {
			arr = append(arr, v)
		}
		err = yamlenc.Encode(arr)
		if err != nil {
			err = fmt.Errorf("error when encoding YAML data: %v", err)
			return nil, err
		}
	}
	return uniqueIDs, nil
}
