package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
	"github.com/lkarlslund/openai-personal-proxy/pkg/wizard"
	"github.com/spf13/cobra"
)

var (
	configServerPath string
)

func init() {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Run server configuration wizard",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadServerConfig(configServerPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					cfg = config.NewDefaultServerConfig()
				} else {
					return fmt.Errorf("load server config: %w", err)
				}
			}
			return wizard.RunServerWizard(configServerPath, cfg)
		},
	}

	configCmd.Flags().StringVar(&configServerPath, "server-config", config.DefaultServerConfigPath(), "Server config TOML path")
	rootCmd.AddCommand(configCmd)
}
