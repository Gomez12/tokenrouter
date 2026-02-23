package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "openai-personal-proxy",
	Short: "OpenAI-compatible personal proxy",
	Long:  "OpenAI-compatible personal proxy with provider aggregation, auth, and admin UI.",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	rootCmd.SilenceUsage = true
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() == 0 {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: running as root")
		}
		return nil
	}
}
