package main

import (
	"strings"

	"github.com/iexpurgator/gom/lib/go_fmt"
)

func HDSD() {
	maxLength := 120
	str_hdsd := "Giới thiệu: Công cụ kiểm thử leo thang đặc guyền trên Windows thông qua các giao thức xác thực. Công cụ sử dụng câu lệnh kiểm tra quyền của người dùng trước và sau khi thực hiện tấn công, kịch bản/hình thức tấn công được cài đặt trong file config.yaml (tuỳ chỉnh). \n\n Khi sử dụng công cụ cần có file cấu hình .yaml có dạng như sau: \n - att_name: \033[90m(tên của kỹ thuật tấn công)\033[0m \n   att_cmd: \033[90m(lệnh thực thi tấn công)\033[0m \n   cred_cmd: \033[90m(lệnh thực thi thu thập thông tin quyền của người dùng, nên sử dụng whoami)\033[0m \n   cred_dir: \033[90m(đường dẫn lưu file chứa thông tin quyền của người dùng)\033[0m \n   cred_file_pre: \033[90m(tên file chứa thông tin quyền của người dùng trước khi tấn công)\033[0m \n   cred_file_aft: \033[90m(tên file chứa thông tin quyền của người dùng sau khi tấn công)\033[0m \n   rem_att: \033[90m(tấn công từ xa - truỳ chọn, nếu không có thì bỏ qua)\033[0m \n     remcon_port: \033[90m(cổng dịch vụ tấn công từ xa)\033[0m \n     remcon_cmd: \033[90m(lệnh tạo revsershell để thi tấn công từ xa)\033[0m \n     remcon_delay: \033[90m(thời gian chờ khi gửi và nhận phản hồi của revsershell)\033[0m \n\n Các trường thông tin khác có thể xem chi tiết trong phần -h hoặc --help."

	var sb strings.Builder
	words := strings.Split(str_hdsd, " ")
	lineLength := 0

	for _, word := range words {
		wordLength := len(word)
		// Wrap to the next line if adding the word exceeds the maximum length
		if lineLength+wordLength > maxLength {
			sb.WriteString("\n")
			lineLength = 0
		}

		// Add the word to the line
		if strings.HasPrefix(word, "\n") {
			sb.WriteString(word)
			lineLength = 0
		} else {
			sb.WriteString(word + " ")
			lineLength += wordLength + 1
		}
	}

	go_fmt.Console.Println(sb.String())
}
