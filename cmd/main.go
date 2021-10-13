package main

import (
	"encoding/json"
	"fmt"
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"www.velocidex.com/golang/oleparse"
)

var (
	app  = kingpin.New("oleparse", "Parse Office files.")
	file = app.Arg("file", "File to load").Required().Strings()
)

func doParse() error {
	for _, f := range *file {
		macros, err := oleparse.ParseFile(f)
		if err != nil {
			return fmt.Errorf("While parsing %v: %w", f, err)
		}

		serialized, err := json.MarshalIndent(macros, " ", " ")
		kingpin.FatalIfError(err, "JSON")

		fmt.Println(string(serialized))
	}
	return nil
}

func main() {
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate).DefaultEnvars()
	kingpin.MustParse(app.Parse(os.Args[1:]))

	err := doParse()
	kingpin.FatalIfError(err, "Parsing")
}
