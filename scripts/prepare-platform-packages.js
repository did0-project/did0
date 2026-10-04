#!/usr/bin/env node

/**
 * scripts/prepare-platform-packages.js
 *
 * Prepares scoped platform packages under npm/ for multi-platform distribution.
 * Generates package.json, README.md, and stages prebuilt binaries for each target.
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const NPM_OUT_DIR = path.join(ROOT_DIR, 'npm');
const PREBUILDS_DIR = path.join(ROOT_DIR, 'prebuilds');

const rootPackageJson = JSON.parse(
  fs.readFileSync(path.join(ROOT_DIR, 'package.json'), 'utf8')
);

const PLATFORMS = [
  {
    id: 'darwin-arm64',
    pkgName: '@did0/binding-darwin-arm64',
    dirName: 'binding-darwin-arm64',
    description: 'macOS Apple Silicon (arm64)',
    artifactName: 'did0.darwin-arm64.node',
    os: ['darwin'],
    cpu: ['arm64'],
  },
  {
    id: 'darwin-x64',
    pkgName: '@did0/binding-darwin-x64',
    dirName: 'binding-darwin-x64',
    description: 'macOS Intel (x64)',
    artifactName: 'did0.darwin-x64.node',
    os: ['darwin'],
    cpu: ['x64'],
  },
  {
    id: 'linux-x64-gnu',
    pkgName: '@did0/binding-linux-x64-gnu',
    dirName: 'binding-linux-x64-gnu',
    description: 'Linux glibc (x64)',
    artifactName: 'did0.linux-x64-gnu.node',
    os: ['linux'],
    cpu: ['x64'],
  },
  {
    id: 'linux-x64-musl',
    pkgName: '@did0/binding-linux-x64-musl',
    dirName: 'binding-linux-x64-musl',
    description: 'Linux musl (x64 / Alpine Docker)',
    artifactName: 'did0.linux-x64-musl.node',
    os: ['linux'],
    cpu: ['x64'],
  },
  {
    id: 'linux-arm64-gnu',
    pkgName: '@did0/binding-linux-arm64-gnu',
    dirName: 'binding-linux-arm64-gnu',
    description: 'Linux glibc (arm64 / Graviton / Raspberry Pi)',
    artifactName: 'did0.linux-arm64-gnu.node',
    os: ['linux'],
    cpu: ['arm64'],
  },
  {
    id: 'linux-arm64-musl',
    pkgName: '@did0/binding-linux-arm64-musl',
    dirName: 'binding-linux-arm64-musl',
    description: 'Linux musl (arm64 / Alpine Docker ARM)',
    artifactName: 'did0.linux-arm64-musl.node',
    os: ['linux'],
    cpu: ['arm64'],
  },
];

function preparePackages() {
  console.log(`📦 Preparing scoped platform packages for did0 v${rootPackageJson.version}...`);

  if (!fs.existsSync(NPM_OUT_DIR)) {
    fs.mkdirSync(NPM_OUT_DIR, { recursive: true });
  }

  for (const plat of PLATFORMS) {
    const pkgDir = path.join(NPM_OUT_DIR, plat.dirName);
    if (!fs.existsSync(pkgDir)) {
      fs.mkdirSync(pkgDir, { recursive: true });
    }

    const pkgJson = {
      name: plat.pkgName,
      version: rootPackageJson.version,
      description: `Precompiled native Node-API binary of did0 for ${plat.description}`,
      main: 'did0.node',
      files: ['did0.node', 'README.md'],
      os: plat.os,
      cpu: plat.cpu,
      author: rootPackageJson.author,
      license: rootPackageJson.license,
      repository: rootPackageJson.repository,
      bugs: rootPackageJson.bugs,
      homepage: rootPackageJson.homepage,
      publishConfig: {
        access: 'public',
      },
    };

    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify(pkgJson, null, 2) + '\n',
      'utf8'
    );

    const readmeContent = `# ${plat.pkgName}\n\nThis is the platform-specific precompiled native Node-API binary of **\`@did0/core\`** for **${plat.description}**.\n\nInstall the main package:\n\`\`\`bash\nnpm install @did0/core\n\`\`\`\n`;
    fs.writeFileSync(path.join(pkgDir, 'README.md'), readmeContent, 'utf8');

    const srcArtifact = path.join(PREBUILDS_DIR, plat.artifactName);
    const destArtifact = path.join(pkgDir, 'did0.node');

    if (fs.existsSync(srcArtifact)) {
      fs.copyFileSync(srcArtifact, destArtifact);
      console.log(`  ✅ Staged ${plat.pkgName} with binary (${plat.artifactName})`);
    } else {
      console.log(`  ⚠️  Prepared ${plat.pkgName} (binary ${plat.artifactName} not yet in prebuilds/)`);
    }
  }

  console.log(`\n✨ Successfully prepared all ${PLATFORMS.length} platform packages in npm/`);
}

/**
 * Adds the platform packages to the root package.json as optionalDependencies.
 * They are not committed because the packages do not exist on the registry
 * until the release job publishes them, which would break `npm ci`.
 */
function injectOptionalDependencies() {
  const pkgPath = path.join(ROOT_DIR, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  pkg.optionalDependencies = {};
  for (const plat of PLATFORMS) {
    pkg.optionalDependencies[plat.pkgName] = pkg.version;
  }
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');
  console.log(`  🔗 Injected ${PLATFORMS.length} optionalDependencies into package.json`);
}

preparePackages();
if (process.argv.includes('--inject-optional')) {
  injectOptionalDependencies();
}
