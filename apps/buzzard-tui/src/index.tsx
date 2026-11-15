#!/usr/bin/env node
import React from 'react';
import * as path from 'node:path';
import { runFullScreenApp } from './terminal/screen.js';
import { App } from './App.js';

let workspace = process.cwd();
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--workspace' || args[i] === '-w') {
    if (args[i + 1]) {
      workspace = path.resolve(args[i + 1]!);
      i++;
    }
  }
}

// Launch application in terminal alternate screen buffer
runFullScreenApp(<App workspace={workspace} />);
