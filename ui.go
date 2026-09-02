package main

import (
	"fmt"
	"io"
)

type uiCmd int

const (
	uiCmdInit uiCmd = iota
	uiCmdUpdate
	uiCmdBelow
)

type uiMsg struct {
	cmd  uiCmd
	idx  int
	text string
}

// UI serializes console output for multi-tunnel mode: all lines go through
// one writer goroutine so parallel tunnels never interleave mid-line.
type UI struct {
	ch chan uiMsg
	w  io.Writer
}

func NewUI(w io.Writer) *UI {
	u := &UI{
		ch: make(chan uiMsg, 256),
		w:  w,
	}
	go u.run()
	return u
}

func (u *UI) Start(header string, n int) {
	u.ch <- uiMsg{cmd: uiCmdInit, text: header}
}

func (u *UI) Update(idx int, line string) {
	u.ch <- uiMsg{cmd: uiCmdUpdate, idx: idx, text: line}
}

func (u *UI) Below(text string) {
	u.ch <- uiMsg{cmd: uiCmdBelow, text: text}
}

func (u *UI) run() {
	for m := range u.ch {
		switch m.cmd {
		case uiCmdInit, uiCmdUpdate, uiCmdBelow:
			fmt.Fprintln(u.w, m.text)
		}
	}
}
