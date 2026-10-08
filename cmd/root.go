/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// Stores the variables that are needed by the commands
var timeout int
var target string
var ports string
var protocol string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "porttrait",
	Short: "A tool for fingerprinting services and grabbing banners",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "T", 10, "Length of timeout")
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Domain to be targeted")
	rootCmd.PersistentFlags().StringVarP(&ports, "ports", "p", "", "Port to be targeted")
	rootCmd.PersistentFlags().StringVarP(&protocol, "protocol", "P", "tcp", "Protocol to be used (tcp, udp or both)")
}