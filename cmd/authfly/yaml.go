package main

import (
	"reflect"

	"github.com/authfly/cli/server/deploy"
	"gopkg.in/yaml.v3"
)

func yamlInto(b []byte, c *deploy.Config) error { return yaml.Unmarshal(b, c) }

// overlay copies every non-zero field of f (the flags) over c (the --config file).
func overlay(c, f *deploy.Config) { merge(reflect.ValueOf(c).Elem(), reflect.ValueOf(f).Elem()) }

func merge(dst, src reflect.Value) {
	for i := 0; i < src.NumField(); i++ {
		if !dst.Field(i).CanSet() {
			continue
		}
		s := src.Field(i)
		if s.Kind() == reflect.Struct {
			merge(dst.Field(i), s)
		} else if !s.IsZero() {
			dst.Field(i).Set(s)
		}
	}
}
