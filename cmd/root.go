package cmd

import (
	"fmt"
	"os"

	"github.com/lkarlslund/tokenrouter/pkg/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "torod",
	Short: "TokenRouter daemon",
	Long:  "TokenRouter daemon with provider aggregation, auth, and admin UI.",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() == 0 {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: running as root")
		}
		return nil
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print torod version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Detailed("torod"))
		},
	})
}
