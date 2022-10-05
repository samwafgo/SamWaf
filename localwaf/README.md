<p style="display:flex; justify-content: center">

</p>
<p align="center">
  <a href="https://tdesign.tencent.com/starter/vue/#/dashboard/base" target="_blank">
    <img alt="TDesign Logo" width="200" src="https://tdesign.gtimg.com/starter/brand-logo.svg">
  </a>
</p>

<p align="center">
  <a href="https://nodejs.org/en/about/releases/"><img src="https://img.shields.io/node/v/vite.svg" alt="node compatility"></a>
  <a href="https://github.com/Tencent/tdesign-vue/blob/develop/LICENSE">
    <img src="https://img.shields.io/npm/l/tdesign-vue.svg?sanitize=true" alt="License">
  </a>
</p>

English | [简体中文](./README-zh_CN.md) 
### Introduction

TDesign Vue Starter is a TDesign-based project developed with `Vue2`, `Vite`. It can be customized theme configuration, and aims to provide project out-of-the-box, configuration-style middle and background projects.

<p>
  <a href="http://tdesign.tencent.com/starter/vue/">Live Preview</a>
  ·
  <a href="https://tdesign.tencent.com/starter/docs/vue/get-started">Documentation</a>
</p>

<img src="docs/docs-starter.png">

### Features

- Various provided pages for develop
- Complete directory structure for develop
- Code specification configuration
- Support dark mode
- Custom theme colors
- Various space layouts
- Mock data scheme

### Usage

> Initialize project with our CLI tool `tdesign-starter-cli` 

```bash
## install tdesign-starter-cli
npm i tdesign-starter-cli@latest -g

## create project
td-starter init
```

### Develop

```bash
## install dependencies
npm install

## set up
npm run dev
```

### Build

```bash
## build
npm run build

## build for test
npm run build:test
```


### Contributing Guide

We welcome contributions to our project. Create your [Issue](https://github.com/tencent/tdesign-vue-starter/issues/new/choose) or Submit your [Pull Request](https://github.com/Tencent/tdesign-vue-starter/pulls).

#### Pull Request

1. Fork it!
2. Create your branch: `git checkout -b feat/xxxx`
3. Commit: `git commit -a 'feat(project): describe'`
4. Push: `git push origin feat/xxxx`
5. New Pull Request `pull request`

#### Commit Specification

- [Angular Convention](https://github.com/conventional-changelog/conventional-changelog/tree/master/packages/conventional-changelog-angular)
- [Vue Style Guide](https://v3.vuejs.org/style-guide/#rule-categories)

### Compatibility

| [<img src="https://raw.githubusercontent.com/alrra/browser-logos/master/src/edge/edge_48x48.png" alt="IE / Edge" width="24px" height="24px" />](http://godban.github.io/browsers-support-badges/)</br> IE / Edge | [<img src="https://raw.githubusercontent.com/alrra/browser-logos/master/src/firefox/firefox_48x48.png" alt="Firefox" width="24px" height="24px" />](http://godban.github.io/browsers-support-badges/)</br>Firefox | [<img src="https://raw.githubusercontent.com/alrra/browser-logos/master/src/chrome/chrome_48x48.png" alt="Chrome" width="24px" height="24px" />](http://godban.github.io/browsers-support-badges/)</br>Chrome | [<img src="https://raw.githubusercontent.com/alrra/browser-logos/master/src/safari/safari_48x48.png" alt="Safari" width="24px" height="24px" />](http://godban.github.io/browsers-support-badges/)</br>Safari |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Edge >=84                                                                                                                                                                                                        | Firefox >=83                                                                                                                                                                                                      | Chrome >=84                                                                                                                                                                                                   | Safari >=14.1                                                                                                                                                                                                 |

### License

The MIT License. Please see [the license file](LICENSE) for more information.
