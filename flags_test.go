package main

import (
	"flag"
	"reflect"
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantPos       []string
		wantDebug     bool
		wantPortSpec  string
		wantThreads   int
		wantType      int
		wantUser      string
		wantPass      string
		wantSalt      string
		wantSmartpss  bool
		wantPool      int
		wantTCPRelay  bool
		wantInfo      bool
		wantLogRetry  bool
		wantHBTimeout time.Duration
	}{
		{
			name:          "serial only",
			args:          []string{"ABC123456"},
			wantPos:       []string{"ABC123456"},
			wantPool:      50,
			wantThreads:   3,
			wantHBTimeout: 10 * time.Second,
		},
		{
			name:          "serial first, flags after",
			args:          []string{"ABC123456", "-p", "5080:80", "-d"},
			wantPos:       []string{"ABC123456"},
			wantDebug:     true,
			wantPortSpec:  "5080:80",
			wantPool:      50,
			wantThreads:   3,
			wantHBTimeout: 10 * time.Second,
		},
		{
			name:          "flags first, serial middle, flags after",
			args:          []string{"-d", "ABC123456", "-p", "5080:80", "-mt", "4"},
			wantPos:       []string{"ABC123456"},
			wantDebug:     true,
			wantPortSpec:  "5080:80",
			wantThreads:   4,
			wantPool:      50,
			wantHBTimeout: 10 * time.Second,
		},
		{
			name:          "auth flags with type 1",
			args:          []string{"ABC123456", "-t", "1", "-u", "admin", "-P", "secret", "-s", "salt123"},
			wantPos:       []string{"ABC123456"},
			wantType:      1,
			wantUser:      "admin",
			wantPass:      "secret",
			wantSalt:      "salt123",
			wantPool:      50,
			wantThreads:   3,
			wantHBTimeout: 10 * time.Second,
		},
		{
			name:          "long auth flags",
			args:          []string{"--type", "1", "--username", "admin", "--password", "secret", "--randsalt", "salt123", "ABC123456"},
			wantPos:       []string{"ABC123456"},
			wantType:      1,
			wantUser:      "admin",
			wantPass:      "secret",
			wantSalt:      "salt123",
			wantPool:      50,
			wantThreads:   3,
			wantHBTimeout: 10 * time.Second,
		},
		{
			name:          "smartpss short flag",
			args:          []string{"-2", "ABC123456"},
			wantPos:       []string{"ABC123456"},
			wantSmartpss:  true,
			wantPool:      50,
			wantThreads:   3,
			wantHBTimeout: 10 * time.Second,
		},
		{
			name:          "smart-pss dash flag",
			args:          []string{"--smart-pss", "ABC123456"},
			wantPos:       []string{"ABC123456"},
			wantSmartpss:  true,
			wantPool:      50,
			wantThreads:   3,
			wantHBTimeout: 10 * time.Second,
		},
		{
			name:          "pools flag",
			args:          []string{"--pools", "25", "ABC123456"},
			wantPos:       []string{"ABC123456"},
			wantPool:      25,
			wantThreads:   3,
			wantHBTimeout: 10 * time.Second,
		},
		{
			name:          "tcp relay and log retries and custom heartbeat",
			args:          []string{"-R", "-lr", "-hb", "5s", "--info", "ABC123456"},
			wantPos:       []string{"ABC123456"},
			wantTCPRelay:  true,
			wantLogRetry:  true,
			wantInfo:      true,
			wantHBTimeout: 5 * time.Second,
			wantPool:      50,
			wantThreads:   3,
		},
		{
			name:          "terminator -- preserves flags as positional",
			args:          []string{"-d", "--", "ABC123456", "-p", "80:80"},
			wantPos:       []string{"ABC123456", "-p", "80:80"},
			wantDebug:     true,
			wantPool:      50,
			wantThreads:   3,
			wantHBTimeout: 10 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)

			var debug, logRetries, infoMode, tcpRelayMode bool
			var smartpssPreset bool
			var poolSize int
			var dtype int
			var username, password, randsalt string
			var threads int
			var portSpec string
			var hbTimeout time.Duration

			fs.BoolVar(&debug, "debug", false, "")
			fs.BoolVar(&debug, "d", false, "")
			fs.BoolVar(&infoMode, "info", false, "")
			fs.BoolVar(&tcpRelayMode, "R", false, "")
			fs.BoolVar(&tcpRelayMode, "tcp-relay", false, "")
			fs.BoolVar(&smartpssPreset, "2", false, "")
			fs.BoolVar(&smartpssPreset, "smartpss", false, "")
			fs.BoolVar(&smartpssPreset, "smart-pss", false, "")
			fs.IntVar(&poolSize, "pool", 50, "")
			fs.IntVar(&poolSize, "pools", 50, "")
			fs.IntVar(&dtype, "t", 0, "")
			fs.IntVar(&dtype, "type", 0, "")
			fs.StringVar(&username, "u", "", "")
			fs.StringVar(&username, "username", "", "")
			fs.StringVar(&password, "P", "", "")
			fs.StringVar(&password, "password", "", "")
			fs.StringVar(&randsalt, "s", "", "")
			fs.StringVar(&randsalt, "randsalt", "", "")
			fs.StringVar(&portSpec, "port", "", "")
			fs.StringVar(&portSpec, "p", "", "")
			fs.IntVar(&threads, "threads", 3, "")
			fs.IntVar(&threads, "mt", 3, "")
			fs.BoolVar(&logRetries, "log-retries", false, "")
			fs.BoolVar(&logRetries, "lr", false, "")
			fs.DurationVar(&hbTimeout, "heartbeat-timeout", 10*time.Second, "")
			fs.DurationVar(&hbTimeout, "hb", 10*time.Second, "")

			pos, err := parseArgs(fs, tc.args)
			if err != nil {
				t.Fatalf("parseArgs error: %v", err)
			}
			if !reflect.DeepEqual(pos, tc.wantPos) {
				t.Errorf("positional: got %v, want %v", pos, tc.wantPos)
			}
			if debug != tc.wantDebug {
				t.Errorf("debug: got %v, want %v", debug, tc.wantDebug)
			}
			if portSpec != tc.wantPortSpec {
				t.Errorf("portSpec: got %v, want %v", portSpec, tc.wantPortSpec)
			}
			if threads != tc.wantThreads {
				t.Errorf("threads: got %v, want %v", threads, tc.wantThreads)
			}
			if dtype != tc.wantType {
				t.Errorf("dtype: got %v, want %v", dtype, tc.wantType)
			}
			if username != tc.wantUser {
				t.Errorf("username: got %v, want %v", username, tc.wantUser)
			}
			if password != tc.wantPass {
				t.Errorf("password: got %v, want %v", password, tc.wantPass)
			}
			if randsalt != tc.wantSalt {
				t.Errorf("randsalt: got %v, want %v", randsalt, tc.wantSalt)
			}
			if smartpssPreset != tc.wantSmartpss {
				t.Errorf("smartpssPreset: got %v, want %v", smartpssPreset, tc.wantSmartpss)
			}
			if poolSize != tc.wantPool {
				t.Errorf("poolSize: got %v, want %v", poolSize, tc.wantPool)
			}
			if tcpRelayMode != tc.wantTCPRelay {
				t.Errorf("tcpRelayMode: got %v, want %v", tcpRelayMode, tc.wantTCPRelay)
			}
			if infoMode != tc.wantInfo {
				t.Errorf("infoMode: got %v, want %v", infoMode, tc.wantInfo)
			}
			if logRetries != tc.wantLogRetry {
				t.Errorf("logRetries: got %v, want %v", logRetries, tc.wantLogRetry)
			}
			if hbTimeout != tc.wantHBTimeout {
				t.Errorf("hbTimeout: got %v, want %v", hbTimeout, tc.wantHBTimeout)
			}
		})
	}
}
