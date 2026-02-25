package cmd

import (
	"fmt"
	"os"

	log "github.com/charmbracelet/log"
	"github.com/lkarlslund/tokenrouter/pkg/logutil"
	"github.com/lkarlslund/tokenrouter/pkg/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "torod",
	Short: "TokenRouter daemon",
	Long:  "TokenRouter daemon with provider aggregation, auth, and admin UI.",
}

var rootLogLevel string

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := logutil.Configure(rootLogLevel); err != nil {
			return err
		}
		if os.Geteuid() == 0 {
			log.Warn("running as root")
		}
		return nil
	}
	rootCmd.PersistentFlags().StringVar(&rootLogLevel, "loglevel", "info", "Log level (trace, debug, info, warn, error, fatal)")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print torod version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Detailed("torod"))
		},
	})
}
