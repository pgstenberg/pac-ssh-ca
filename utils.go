package main

import "encoding/json"

func jsonMarshalUnmarshal[T any](value any, target *T) error {
	inrec, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(inrec, target); err != nil {
		return err
	}
	return nil
}

func stringSliceToBytes(target []string) [][]byte {
	l := [][]byte{}
	for _, v := range target {
		l = append(l, []byte(v))
	}
	return l
}
