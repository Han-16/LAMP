package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

func SelectTargetIndex(api frontend.API, array []frontend.Variable, indexBits []frontend.Variable) frontend.Variable {
	currentLayer := array

	for d := 0; d < len(indexBits); d++ {
		nextLayer := make([]frontend.Variable, 0, (len(currentLayer)+1)/2)

		for j := 0; j < len(currentLayer); j += 2 {
			left := currentLayer[j]

			right := currentLayer[j]
			if j+1 < len(currentLayer) {
				right = currentLayer[j+1]
			}

			// bit=0 => left, bit=1 => right
			selected := api.Select(indexBits[d], right, left)
			nextLayer = append(nextLayer, selected)
		}
		currentLayer = nextLayer
	}

	return currentLayer[0]
}

func Fold(api frontend.API, lhs, rhs []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	for j := 0; j < len(lhs); j++ {
		acc = api.Add(acc, api.Mul(lhs[j], rhs[j]))
	}
	return acc
}

func VerifyRSEncoding(
	api frontend.API,
	k, n int,
	domainK, weightsK []fr.Element, // K 도메인 정보 추가
	domainN, weightsN []fr.Element, // N 도메인 정보
	vecValues []frontend.Variable, // [K] 원본 평가값 (VecX)
	encValues []frontend.Variable, // [N] 코드워드 (EncX)
	z frontend.Variable,
) {
	// Step 1: K 도메인 위에서 Barycentric 공식으로 f(z) 계산
	numK := frontend.Variable(0) // 분자
	denK := frontend.Variable(0) // 분모

	for i := 0; i < k; i++ {
		zMinusW := api.Sub(z, domainK[i])
		invZMinusW := api.Inverse(zMinusW)

		term := api.Mul(weightsK[i], invZMinusW) // \lambda_{K,i} / (z - w_K^i)
		denK = api.Add(denK, term)

		numTerm := api.Mul(term, vecValues[i])
		numK = api.Add(numK, numTerm)
	}

	// Step 2: N 도메인 위에서 Barycentric 공식으로 g(z) 계산
	numN := frontend.Variable(0)
	denN := frontend.Variable(0)

	for i := 0; i < n; i++ {
		zMinusW := api.Sub(z, domainN[i])
		invZMinusW := api.Inverse(zMinusW)

		term := api.Mul(weightsN[i], invZMinusW) // \lambda_{N,i} / (z - w_N^i)
		denN = api.Add(denN, term)

		numTerm := api.Mul(term, encValues[i])
		numN = api.Add(numN, numTerm)
	}

	// Step 3: Decision
	// (numK / denK) == (numN / denN) 인지 확인
	// 나눗셈을 피하기 위해 Cross-multiplication(교차 곱)으로 증명: numK * denN == numN * denK
	lhs := api.Mul(numK, denN)
	rhs := api.Mul(numN, denK)

	api.AssertIsEqual(lhs, rhs)
}
