package main

import "net"

func ternary(condition bool, trueValue interface{}, falseValue interface{}) interface{} {
	if condition {
		return trueValue
	}
	return falseValue
}

func readUntilNull(conn net.Conn) ([]byte, error) {
	buffer := make([]byte, 4096)
	data := []byte{}
	for {
		readedLen, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}
		data = append(data, buffer[:readedLen]...)
		if readedLen < 4096 {
			break
		}
	}
	return data, nil
}
