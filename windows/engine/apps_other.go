//go:build !windows

package main

func routingApplications(values []string) []string { return values }
func installedBlueStacksApplications() []string    { return nil }
