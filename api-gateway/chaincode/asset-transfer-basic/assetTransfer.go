/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"github.com/hyperledger/fabric-samples/asset-transfer-basic/chaincode-go/chaincode"
)

func main() {
	cc, err := contractapi.NewChaincode(&chaincode.GatewayContract{})
	if err != nil {
		log.Panicf("Error creating api-gateway chaincode: %v", err)
	}

	if err := cc.Start(); err != nil {
		log.Panicf("Error starting api-gateway chaincode: %v", err)
	}
}
