package client

import (
    "encoding/json"
	"fmt"
)

var cmdGetAll = &Command{
	Run:       runGetAll,
	UsageLine: "getall",
	Short:     "gets all primary key values which are Read accesible by user",
	Long: `
Get All returns all primary kay-value pairs which are Read accessible by user in json string.

This was provided for convenience usage in fab scripts in Aarki.

See also: knox get, knox create, knox daemon
	`,
}

func runGetAll(cmd *Command, args []string) *ErrorStatus {
	keys, err := cli.GetAll()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("Error getting all keys: %s", err.Error()), false}
	}
	simplified := make(map[string]string)
	for _, k := range keys {
		simplified[k.ID] = string(k.VersionList.GetPrimary().Data)
	}
	data, err := json.Marshal(simplified)
	if err != nil {
		return &ErrorStatus{err, false}
	}
	fmt.Printf("%s", string(data))
	return nil
}
