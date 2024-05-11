package main

import "encoding/json"

func marshalUnmarshal(target interface{}, value any) error {
	inrec, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(inrec, target); err != nil {
		return err
	}
	return nil
}
func AnyToMap(value any) (map[string]interface{}, error) {
	var inputMap map[string]interface{}
	if err := marshalUnmarshal(inputMap, value); err != nil {
		return nil, err
	}
	return inputMap, nil
}
