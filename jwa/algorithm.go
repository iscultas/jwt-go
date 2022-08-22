package jwa

type Algorithmer interface {
	Header() map[string]any
}

type algorithm string

func (algorithm_ algorithm) Header() map[string]any {
	return map[string]any{"alg": algorithm_}
}
