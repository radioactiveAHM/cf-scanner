package main

import (
	"math"
)

func Calc_jitter(list []float64) float64 {
	average := calc_average(list)
	zigma := 0.0
	for _, element := range list {
		zigma += math.Abs(element - average)
	}
	return zigma / float64(len(list))
}

func calc_average(list []float64) float64 {
	sum := 0.0
	for _, element := range list {
		sum += element
	}
	return sum / float64(len(list))
}
