#!/usr/bin/env node
import React from 'react';
import * as path from 'node:path';
import { runFullScreenApp } from './terminal/screen.js';
import { App } from './App.js';

let workspace = process.cwd();
let brand = 'BUZZARD CODE';
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--workspace' || args[i] === '-w') {
    if (args[i + 1]) {
      let raw = args[i + 1]!;
      raw = raw.replace(/^["']+|["']+$/g, '');
      workspace = path.resolve(raw);
      i++;
    }
  } else if (args[i] === '--brand' || args[i] === '-b') {
    if (args[i + 1]) {
      brand = args[i + 1]!.replace(/^["']+|["']+$/g, '');
      i++;
    }
  } else if (args[i] === '--go') {
    brand = 'BUZZARD GO';
  }
}

// Launch application in terminal alternate screen buffer
runFullScreenApp(<App workspace={workspace} brand={brand} />);
