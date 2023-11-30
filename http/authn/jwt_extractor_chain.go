package authn

import "net/http"

// TokenExtractorChain allows you to chain multiple TokenExtractor objects together.
type TokenExtractorChain []TokenExtractor

func NewTokenExtractorChain() TokenExtractorChain {
	return []TokenExtractor{}
}

func (chain TokenExtractorChain) Append(extractor TokenExtractor) TokenExtractorChain {
	return append(chain, extractor)
}

func (chain TokenExtractorChain) ExtractRequestToken(request *http.Request) (string, error) {
	for _, extractor := range chain {
		tokenStr, err := extractor.ExtractRequestToken(request)
		if err != nil {
			return "", err
		}
		if tokenStr != "" {
			return tokenStr, nil
		}
	}

	return "", nil
}
