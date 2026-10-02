module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.+(ts|tsx|js)', '**/?(*.)+(spec|test).+(ts|tsx|js)'],
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest',
    // @sveltejs/acorn-typescript ships ESM only. Node >= 20.19 can require() it
    // directly, but Jest's module loader can't, so convert just that package.
    '^.+/node_modules/@sveltejs/acorn-typescript/.+\\.js$': [
      'ts-jest',
      { tsconfig: { allowJs: true, module: 'commonjs' }, diagnostics: false },
    ],
  },
  transformIgnorePatterns: ['/node_modules/(?!@sveltejs/acorn-typescript/)'],
};
