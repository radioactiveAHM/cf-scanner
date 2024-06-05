package main

import (
	"math"
)

func Calc_jitter(list []float64) float64 {
	average := calc_average(list)
	zigma := 0.0
	for _, element := range list {
		zigma += (element - average) * (element - average)
	}
	return math.Sqrt((1.0 / float64(len(list)) * zigma))
}

func calc_average(list []float64) float64 {
	sum := 0.0
	for _, element := range list {
		sum += element
	}
	return sum / float64(len(list))
}
