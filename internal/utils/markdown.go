package utils

import (
	"fmt"
	"strings"
	"unicode"
)

type Markdown struct {
	Name string
	Data string
}

type MdFunc func(*Markdown)

// WithName 配置文件名
func WithName(name string) MdFunc {
	return func(rep *Markdown) { rep.Name = name }
}

// WithData 配置内容
func WithData(data string) MdFunc {
	return func(rep *Markdown) { rep.Data = data }
}

func NewMarkdown(reps ...MdFunc) *Markdown {
	md := &Markdown{}
	for _, rep := range reps {
		rep(md)
	}
	return md
}

// SetH1 一级标题
func (r *Markdown) SetH1(text string) {
	r.Data += fmt.Sprintf("# %s\n", text)
}

// SetH2 二级标题
func (r *Markdown) SetH2(text string) {
	r.Data += fmt.Sprintf("## %s\n", text)
}

// SetH3 三级标题
func (r *Markdown) SetH3(text string) {
	r.Data += fmt.Sprintf("### %s\n", text)
}

// SetH4 四级标题
func (r *Markdown) SetH4(text string) {
	r.Data += fmt.Sprintf("#### %s\n", text)
}

// SetText 正文
func (r *Markdown) SetText(text string) {
	var newText []string
	for _, str := range strings.Split(text, "\n") {
		//如果是代码，则设置为代码块样式
		//if IsCode(str) {
		//	str = r.SetCode(str)
		//}
		newText = append(newText, str)
	}
	r.Data += fmt.Sprintf("%s\n\n", strings.Join(newText, "\n\n"))
}

// IsCode 若字符串中包含中文字符，则不是代码
func IsCode(input string) bool {
	for _, char := range input {
		if unicode.Is(unicode.Han, char) {
			return false
		}
	}
	return true
}

// SetCode 设置 bash 代码块
func (r *Markdown) SetCode(code string) string {
	return fmt.Sprintf("```bash\n%s\n```", code)
}

// SetUl 设置无序列表
func (r *Markdown) SetUl(texts []string) {
	for _, text := range texts {
		r.Data += fmt.Sprintf("- %s\n", text)
	}
	r.Data += "\n"
}

// SetLi 设置有序列表
func (r *Markdown) SetLi(texts []string) {
	for i, text := range texts {
		r.Data += fmt.Sprintf("%v. %s\n", i+1, text)
	}
	r.Data += "\n"
}

// SetSplice 设置分割线
func (r *Markdown) SetSplice() {
	r.Data += "---\n"
}

// SetTable 设置表格
func (r *Markdown) SetTable(headers []string, rows [][]string) {
	// Header
	r.Data += "| " + strings.Join(headers, " | ") + " |\n"
	// Separator line
	r.Data += "|---" + strings.Repeat(" | ---", len(headers)-1) + " |\n"
	// Rows
	for _, row := range rows {
		r.Data += "| " + strings.Join(row, " | ") + " |\n"
	}
	r.Data += "\n"
}

// SetLink 设置链接
func (r *Markdown) SetLink(text, url string) {
	r.Data += fmt.Sprintf("[%s](%s)\n", text, url)
	r.Data += "\n"
}
