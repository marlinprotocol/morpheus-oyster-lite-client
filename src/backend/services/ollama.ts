import { app, ipcMain } from 'electron';
import { Ollama } from 'ollama';
import { execFile, ChildProcess } from 'child_process';
import fs from 'fs';
import { sendOllamaStatusToRenderer } from '..';
import { MOR_PROMPT } from './prompts';
import axios from 'axios';
import { AbiCoder, ethers } from 'ethers';
// import  createKeccakHash  from 'keccak';
const { keccak256, encodePacked } = require('js-sha3');
const bigInt = require("big-integer");
// import secp256k1 from 'secp256k1';


// events
import { IpcMainChannel } from '../../events';
import {
  createDirectoryElevated,
  executeCommandElevated,
  getExecutablePathByPlatform,
  killProcess,
  runDelayed,
} from './system';

// storage
import { getModelPathFromStorage } from '../storage';
import { logger } from './logger';
import { keccak_256, sha3_256 } from 'js-sha3';
import { ecdsaRecover } from 'secp256k1';

// constants
const DEFAULT_OLLAMA_URL = 'http://13.201.44.4:11434/';

// commands
export const SERVE_OLLAMA_CMD = 'ollama serve';
export const WSL_SERVE_OLLAMA_CMD = 'wsl ollama serve';

// ollama instance
let ollama: Ollama;
let ollamaProcess: ChildProcess | null;

export const loadOllama = async () => {
  let runningInstance = await isOllamaInstanceRunning();

  if (runningInstance) {
    // connect to local instance
    ollama = new Ollama({
      host: DEFAULT_OLLAMA_URL,
    });

    await sendOllamaStatusToRenderer(
      `local instance of ollama is running and connected at ${DEFAULT_OLLAMA_URL}`,
    );

    return true;
  }

  const customAppData = getModelPathFromStorage();
  runningInstance = await packedExecutableOllamaSpawn(customAppData);

  if (runningInstance) {
    // connect to local instance
    ollama = new Ollama({
      host: DEFAULT_OLLAMA_URL,
    });

    await sendOllamaStatusToRenderer(
      `local instance of ollama is running and connected at ${DEFAULT_OLLAMA_URL}`,
    );

    return true;
  }

  ipcMain.emit(IpcMainChannel.Error, `Couldn't start Ollama locally.`);

  return false;
};

export const isOllamaInstanceRunning = async (url?: string): Promise<boolean> => {
  try {
    const usedUrl = url ?? DEFAULT_OLLAMA_URL;

    await sendOllamaStatusToRenderer(`checking if ollama instance is running at ${usedUrl}`);

    const ping = await fetch(usedUrl);

    return ping.status === 200;
  } catch (err) {
    return false;
  }
};

export const packedExecutableOllamaSpawn = async (customDataPath?: string) => {
  await sendOllamaStatusToRenderer(`trying to spawn locally installed ollama`);

  try {
    spawnLocalExecutable(customDataPath);
  } catch (err) {
    console.error(err);
  }

  return await runDelayed(isOllamaInstanceRunning, 100);
};

export const devRunLocalWSLOllama = (customDataPath?: string) => {
  executeCommandElevated(
    WSL_SERVE_OLLAMA_CMD,
    customDataPath ? { OLLAMA_MODELS: customDataPath } : undefined,
  );
};

export const spawnLocalExecutable = async (customDataPath?: string) => {
  try {
    console.log("using local")
    const { executablePath, appDataPath } = getOllamaExecutableAndAppDataPath(customDataPath);

    if (!fs.existsSync(appDataPath)) {
      createDirectoryElevated(appDataPath);
    }

    const env = {
      ...process.env,
      OLLAMA_MODELS: appDataPath,
    };

    ollamaProcess = execFile(executablePath, ['serve'], { env }, (err, stdout, stderr) => {
      if (err) {
        throw new Error(`exec error: ${err.message}`);
      }

      if (stderr) {
        throw new Error(`stderr: ${stderr}`);
      }
    });
  } catch (err) {
    logger.error(err);
  }
};

export const getOllamaExecutableAndAppDataPath = (
  customDataPath?: string,
): {
  executablePath: string;
  appDataPath: string;
} => {
  const appDataPath = customDataPath || app.getPath('userData');
  const executablePath = getExecutablePathByPlatform();

  return {
    executablePath,
    appDataPath,
  };
};

function stringToBigEndianBytes(str:string) {
  const num = parseInt(str, 10); // Parse the string as a base-10 integer
  const buffer = new ArrayBuffer(4); // 32-bit buffer
  const view = new DataView(buffer);

  // Set the 32-bit integer in big-endian format
  view.setUint32(0, num, false);

  // Extract the bytes from the buffer
  const bytes = new Uint8Array(buffer);

  return bytes;
}

const isAddressValid = async (recovered_address: string) => {

  const config = {
    method: 'get',
    url: 'http://13.201.44.4:1500/attestation',
    headers: { }
  };

  let attestation_response = await axios(config);
  let secp256k1_public_key = attestation_response.data["secp256k1_public"];

  const decodedBuffer = Buffer.from(secp256k1_public_key, 'hex');

  const hashedBuffer = keccak256(decodedBuffer);

  const ethereumAddress = '0x' + hashedBuffer.slice(24).toString('hex');

  console.log("Address from attestation", ethereumAddress);

  if (ethereumAddress == recovered_address.toLowerCase()){
    console.log("Address match")
    return true;
  }
  console.log("Address do not match")
  return false;
};


export const askOllama = async (model: string, message: string) => {
  let data = JSON.stringify({
    model,
    messages: [
      {
        role: 'system',
        content: MOR_PROMPT,
      },
      {
        role: 'user',
        content: `Answer the following query in a valid formatted JSON object without comments with both the response and action fields deduced from the user's question. Adhere strictly to JSON syntax without comments. Query: ${message}. Response: { "response":`,
      },
    ],
  })
  let config = {
    method: 'post',
    url: 'http://13.201.44.4:5000/api/chat',
    headers: { 
      'Content-Type': 'application/json'
    },
    data : data
  };
  
  let response = await axios(config);
  let timestamp = response.headers["x-oyster-timestamp"];
  let signature = response.headers["x-oyster-signature"];
  let model_name = response.data["model"];
  let model_response = response.data["message"]["content"];
  let model_prompt = message;
  let abiCoder = new AbiCoder();
  let abi_encoded_data = abiCoder.encode(["string","string","string","string"],
    [model_name,
    `Answer the following query in a valid formatted JSON object without comments with both the response and action fields deduced from the user's question. Adhere strictly to JSON syntax without comments. Query: ${model_prompt}. Response: { "response":`,
    model_response,
    timestamp]
  );
  let hash = ethers.keccak256(ethers.solidityPacked(["string","string","bytes"],["|oyster-hasher|","|ollama_signature_parameters|",abi_encoded_data]));
  console.log("Hash : ",hash);
  let sig = ethers.Signature.from("0x"+signature);
  let recoverAddress = ethers.recoverAddress(hash,sig);
  console.log("Recovered address : ",recoverAddress);

  if(await isAddressValid(recoverAddress)){
    return response.data;
  }
};


export const getOrPullModel = async (model: string) => {
  await installModelWithStatus(model);

  // init the model on pull to load into memory
  await ollama.chat({ model });

  return findModel(model);
};

export const installModelWithStatus = async (model: string) => {
  const stream = await ollama.pull({
    model,
    stream: true,
  });

  for await (const part of stream) {
    if (part.digest) {
      let percent = 0;

      if (part.completed && part.total) {
        percent = Math.round((part.completed / part.total) * 100);

        await sendOllamaStatusToRenderer(`${part.status} ${percent}%`);
      }
    } else {
      await sendOllamaStatusToRenderer(`${part.status}`);
    }
  }
};

export const findModel = async (model: string) => {
  const allModels = await ollama.list();

  return allModels.models.find((m) => m.name.toLowerCase().includes(model));
};

export const getAllLocalModels = async () => {
  return await ollama.list();
};

export const stopOllama = async () => {
  if (!ollamaProcess) {
    return;
  }

  killProcess(ollamaProcess);

  ollamaProcess.removeAllListeners();
  ollamaProcess = null;
};
