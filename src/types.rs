#![allow(non_snake_case)]
#![allow(non_camel_case_types)]


use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use std::{error::Error, sync::Arc};

use crate::Node;




#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawlV1 {
    pub index: String,
    pub validatorIndex: String,
    pub address: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkchoiceStateV1 {
    pub headBlockHash: String,
    pub safeBlockHash: String,
    pub finalizedBlockHash: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAttributesV2 {
    pub timestamp: String,
    pub prevRandao: String,
    pub suggestedFeeRecipient: String,
    pub withdrawls: Option<Vec<WithdrawlV1>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPayloadV2 {
    pub parentHash: String,
    pub feeRecipient: String,
    pub stateRoot: String,
    pub receiptsRoot: String,
    pub logsBloom: String,
    pub prevRandao: String,
    pub blockNumber: String,
    pub gasLimit: String,
    pub gasUsed: String,
    pub timestamp: String,
    pub extraData: String,
    pub baseFeePerGas: String,
    pub blockHash: String,
    pub transactions: Vec<String>,
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
    terminalTotalDifficulty: String,
    terminalBlockHash: String,
    terminalBlockNumber: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct payloadStatusV1 {
    pub status: ExecutionStatus,
    pub latestValidHash: String,
    pub ValidationError: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct forkchoiceUpdatedV1Response {
    pub jsonrpc: String,
    pub id: u64,
    pub result: (payloadStatusV1, Option<String>),
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
    pub fn set_id(&self, id: u64) -> Result<String, Box<dyn Error>> {
        // we have to set the id field
        let mut fcu = self.clone();
        fcu.id = id;
        let json = serde_json::to_string(&fcu)?;
        Ok(json)
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
pub struct forkchoiceUpdatedV2 {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: (ForkchoiceStateV1, Option<PayloadAttributesV2>),
}

impl forkchoiceUpdatedV2 {
    #[inline(always)]
    pub fn to_db(&self) -> Result<String, Box<dyn Error>> {
        // we have to remove the id field and if present remove the payloadAttributes
        let mut fcu = self.clone();
        fcu.id = 0;

        if fcu.params.1.is_some() {
            fcu.params.1 = None;
        }

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
    pub method: Option<String>,
    pub params: Option<Vec<TransitionConfigurationV1>>,
    pub result: Option<TransitionConfigurationV1>,
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

#[derive(Clone)]
pub struct State {
    pub db: Arc<tokio_postgres::Client>,
    pub jwt_secret: Arc<jsonwebtoken::EncodingKey>,
    pub auth_node: Arc<Node>,
    pub unauth_node: Arc<Node>,
    pub last_legitimate_fcu: Arc<RwLock<Vec<String>>>,  // first should be req second should be res
}