/**
 * Sample Safe Skill for Testing skillguard
 * This file should pass security scanning with score 0
 */

// Safe: Simple utility functions
function add(a, b) {
  return a + b;
}

function multiply(a, b) {
  return a * b;
}

// Safe: String manipulation
function formatMessage(name, greeting = 'Hello') {
  return `${greeting}, ${name}!`;
}

// Safe: Array operations
function filterEvenNumbers(numbers) {
  return numbers.filter(n => n % 2 === 0);
}

// Safe: Object manipulation
function mergeObjects(obj1, obj2) {
  return { ...obj1, ...obj2 };
}

// Safe: Promise-based async function
async function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Safe: Class definition
class Calculator {
  constructor() {
    this.result = 0;
  }

  add(value) {
    this.result += value;
    return this;
  }

  subtract(value) {
    this.result -= value;
    return this;
  }

  getResult() {
    return this.result;
  }

  reset() {
    this.result = 0;
    return this;
  }
}

// Safe: Reading non-sensitive environment variable
const nodeEnv = process.env.NODE_ENV;
console.log(`Running in ${nodeEnv} mode`);

module.exports = {
  add,
  multiply,
  formatMessage,
  filterEvenNumbers,
  mergeObjects,
  delay,
  Calculator
};
