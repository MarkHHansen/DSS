package main

import "fmt"

type sliceStruct struct {
	mitSlice []string
}

func main() {
	MitObjekt := new(sliceStruct)

	MitObjekt.mitSlice = make([]string, 1)
	MitObjekt.mitSlice = append(MitObjekt.mitSlice, "Streng1")

	fmt.Println(MitObjekt.mitSlice)

	MitObjekt.mitSlice = append(MitObjekt.mitSlice, "Streng2")
	fmt.Println(MitObjekt.mitSlice)
}
