package main

import "encoding/json"

func jsonMarshalUnmarshal[T any](value any) (*T, error) {
	var target T
	inrec, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(inrec, target); err != nil {
		return nil, err
	}
	return &target, nil
}
