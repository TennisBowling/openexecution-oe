#![allow(non_snake_case)]
#![allow(non_camel_case_types)]


use ethereum_types::{Address, H256, U256};
use serde::{Deserialize, Serialize};
use std::error::Error;




#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawlV1 {
    pub index: u64,
    pub validatorIndex: u64,
    pub address: Address,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkchoiceStateV1 {
    pub headBlockHash: H256,
    pub safeBlockHash: H256,
    pub finalizedBlockHash: H256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAttributesV1 {
    pub timestamp: u64,
    pub prevRandao: H256,
    pub suggestedFeeRecipient: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAttributesV2 {
    pub timestamp: u64,
    pub prevRandao: H256,
    pub suggestedFeeRecipient: Address,
    pub withdrawls: Option<Vec<WithdrawlV1>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPayloadV2 {
    pub parentHash: H256,
    pub feeRecipient: Address,
    pub stateRoot: H256,
    pub receiptsRoot: H256,
    pub logsBloom: String,
    pub prevRandao: H256,
    pub blockNumber: u64,
    pub gasLimit: u64,
    pub gasUsed: u64,
    pub timestamp: u64,
    pub extraData: Vec<u8>,
    pub baseFeePerGas: U256,
    pub blockHash: H256,
    pub transactions: Vec<Vec<u8>>,
    pub withdrawls: Option<Vec<WithdrawlV1>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    VALID,
    INVALID,
    SYNCING,
    ACCEPTED,
    INVALID_BLOCK_HASH,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionConfigurationV1 {
    terminalTotalDifficulty: U256,
    terminalBlockHash: H256,
    terminalBlockNumber: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct payloadStatusV1 {
    pub status: ExecutionStatus,
    pub latestValidHash: H256,
    pub ValidationError: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct forkchoiceUpdatedV1ResponseResult {
    pub payloadStatus: payloadStatusV1,
    pub payloadId: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct forkchoiceUpdatedV1Response {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Vec<forkchoiceUpdatedV1ResponseResult>,
    pub error: Option<String>,
}

impl forkchoiceUpdatedV1Response {
    #[inline(always)]
    pub fn to_db(&self) -> Result<String, Box<dyn Error>> {
        // we have to remove the id field
        let mut fcu = self.clone();
        fcu.id = 0;
        let json = serde_json::to_string(&fcu)?;
        Ok(json)
    }

    #[inline(always)]
    pub fn set_id(&self, id: u64) -> Result<Self, Box<dyn Error>> {
        // we have to set the id field
        let mut fcu = self.clone();
        fcu.id = id;
        Ok(fcu)
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct newPayloadV1Response {
    pub jsonrpc: String,
    pub id: u64,
    pub result: payloadStatusV1,
    pub error: Option<String>,
}

impl newPayloadV1Response {
    #[inline(always)]
    pub fn to_db(&self) -> Result<String, Box<dyn Error>> {
        // we have to remove the id field
        let mut fcu = self.clone();
        fcu.id = 0;
        let json = serde_json::to_string(&fcu)?;
        Ok(json)
    }

    #[inline(always)]
    pub fn set_id(&self, id: u64) -> Result<String, Box<dyn Error>> {
        // we have to set the id field
        let mut fcu = self.clone();
        fcu.id = id;
        let json = serde_json::to_string(&fcu)?;
        Ok(json)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadAttributes {
    V1(PayloadAttributesV1),
    V2(PayloadAttributesV2),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkchoiceUpdatedV2Params {
    pub forkchoiceState: ForkchoiceStateV1,
    pub payloadAttributes: Option<PayloadAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct forkchoiceUpdatedV2 {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: Vec<ForkchoiceUpdatedV2Params>,
}

impl forkchoiceUpdatedV2 {
    #[inline(always)]
    pub fn to_db(&self) -> Result<String, Box<dyn Error>> {
        // we have to remove the id field
        let mut fcu = self.clone();
        fcu.id = 0;
        let json = serde_json::to_string(&fcu)?;
        Ok(json)
    }
}

// respose for forkchoiceUpdatedV2 is the same as forkchoiceUpdatedV1


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct newPayloadV2 {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: Vec<ExecutionPayloadV2>,
}

// response for newPayloadV2 is the same as newPayloadV1


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct exchangeTransitionConfigurationV1 {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: Vec<TransitionConfigurationV1>,
}

impl exchangeTransitionConfigurationV1 {
    #[inline(always)]
    pub fn to_db(&self) -> Result<String, Box<dyn Error>> {
        // we have to remove the id field
        let mut fcu = self.clone();
        fcu.id = 0;
        let json = serde_json::to_string(&fcu)?;
        Ok(json)
    }

    #[inline(always)]
    pub fn set_id(&self, id: u64) -> Result<String, Box<dyn Error>> {
        // we have to set the id field
        let mut fcu = self.clone();
        fcu.id = id;
        let json = serde_json::to_string(&fcu)?;
        Ok(json)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestMethod {
    engine_ForkchoiceUpdatedV1,
    engine_ForkchoiceUpdatedV2,
    engine_NewPayloadV1,
    engine_NewPayloadV2,
    engine_getPayloadV1,
    engine_getPayloadV2,
    engine_getPayloadBodiesByHashV1,
    engine_getPayloadBodiesByRangeV1,
    engine_exchangeCapabilities,
    engine_exchangeTransitionConfigurationV1,
}
