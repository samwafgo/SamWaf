import { Color } from 'tvision-color';
/* eslint-disable indent */
export type ColorToken = Record<string, string>;
export type ColorSeries = Record<string, ColorToken>;

export const defaultLightColor = [
  '#0052d9',
  '#0594fa',
  '#00a870',
  '#ebb105',
  '#ed7b2f',
  '#e34d59',
  '#ed49b4',
  '#834ec2',
];
export const defaultDarkColor = [
  '#4582e6',
  '#29a4fb',
  '#03a56f',
  '#ca8d03',
  '#ed7b2f',
  '#ea7b84',
  '#f172c5',
  '#ab87d5',
];

export const COLOR_TOKEN: ColorSeries = {
  DEFAULT: {
    '--td-brand-color': '#0052D9',
    '--td-brand-color-1': '#e0ebff',
    '--td-brand-color-2': '#c0d8ff',
    '--td-brand-color-3': '#a1c4ff',
    '--td-brand-color-4': '#81b1ff',
    '--td-brand-color-5': '#5f9bff',
    '--td-brand-color-6': '#3d87ff',
    '--td-brand-color-7': '#176eff',
    '--td-brand-color-8': '#0052D9',
    '--td-brand-color-9': '#0048cd',
    '--td-brand-color-10': '#0035b5',
  },

  CYAN: {
    '--td-brand-color': '#0594FA',
    '--td-brand-color-1': '#d7eefe',
    '--td-brand-color-2': '#aeddfd',
    '--td-brand-color-3': '#84cafd',
    '--td-brand-color-4': '#58b8fc',
    '--td-brand-color-5': '#29a4fb',
    '--td-brand-color-6': '#0594FA',
    '--td-brand-color-7': '#29a4fb',
    '--td-brand-color-8': '#0594FA',
    '--td-brand-color-9': '#0378df',
    '--td-brand-color-10': '#01409b',
  },
  GREEN: {
    '--td-brand-color': '#00A870',
    '--td-brand-color-1': '#8dffd9',
    '--td-brand-color-2': '#00f2a2',
    '--td-brand-color-3': '#00dc92',
    '--td-brand-color-4': '#00c583',
    '--td-brand-color-5': '#00A870',
    '--td-brand-color-6': '#009a5d',
    '--td-brand-color-7': '#00c583',
    '--td-brand-color-8': '#00A870',
    '--td-brand-color-9': '#009a5d',
    '--td-brand-color-10': '#004a14',
  },
  ORANGE: {
    '--td-brand-color': '#ED7B2F',
    '--td-brand-color-1': '#fce5d7',
    '--td-brand-color-2': '#f8cdaf',
    '--td-brand-color-3': '#f4b285',
    '--td-brand-color-4': '#f19659',
    '--td-brand-color-5': '#ED7B2F',
    '--td-brand-color-6': '#e75510',
    '--td-brand-color-7': '#f19659',
    '--td-brand-color-8': '#ED7B2F',
    '--td-brand-color-9': '#e75510',
    '--td-brand-color-10': '#7f0a02',
  },
  RED: {
    '--td-brand-color': '#E34D59',
    '--td-brand-color-1': '#fbe5e7',
    '--td-brand-color-2': '#f7ccd0',
    '--td-brand-color-3': '#f3b2b8',
    '--td-brand-color-4': '#ef989f',
    '--td-brand-color-5': '#ea7b84',
    '--td-brand-color-6': '#E34D59',
    '--td-brand-color-7': '#ea7b84',
    '--td-brand-color-8': '#E34D59',
    '--td-brand-color-9': '#e42c3a',
    '--td-brand-color-10': '#8d0309',
  },
  PINK: {
    '--td-brand-color': '#ED49B4',
    '--td-brand-color-1': '#fce5f4',
    '--td-brand-color-2': '#facae9',
    '--td-brand-color-3': '#f7aede',
    '--td-brand-color-4': '#f491d2',
    '--td-brand-color-5': '#f172c5',
    '--td-brand-color-6': '#ED49B4',
    '--td-brand-color-7': '#f172c5',
    '--td-brand-color-8': '#ED49B4',
    '--td-brand-color-9': '#e80f9d',
    '--td-brand-color-10': '#8f025e',
  },
  PURPLE: {
    '--td-brand-color': '#834EC2',
    '--td-brand-color-1': '#eee6f7',
    '--td-brand-color-2': '#ddceee',
    '--td-brand-color-3': '#ccb6e6',
    '--td-brand-color-4': '#bb9edc',
    '--td-brand-color-5': '#ab87d5',
    '--td-brand-color-6': '#9a6fce',
    '--td-brand-color-7': '#9a6fce',
    '--td-brand-color-8': '#834EC2',
    '--td-brand-color-9': '#783ac3',
    '--td-brand-color-10': '#4c1397',
  },
  YELLOW: {
    '--td-brand-color': '#EBB105',
    '--td-brand-color-1': '#fde9ab',
    '--td-brand-color-2': '#fbd152',
    '--td-brand-color-3': '#EBB105',
    '--td-brand-color-4': '#dda204',
    '--td-brand-color-5': '#ca8d03',
    '--td-brand-color-6': '#b67803',
    '--td-brand-color-7': '#fbd152',
    '--td-brand-color-8': '#EBB105',
    '--td-brand-color-9': '#dda204',
    '--td-brand-color-10': '#603100',
  },
};

export const LIGHT_CHART_COLORS: ColorToken = {
  textColor: 'rgba(0, 0, 0, 0.9)',
  placeholderColor: 'rgba(0, 0, 0, 0.35)',
  borderColor: '#dcdcdc',
  containerColor: '#fff',
};

export const DARK_CHART_COLORS: ColorToken = {
  textColor: 'rgba(255, 255, 255, 0.9)',
  placeholderColor: 'rgba(255, 255, 255, 0.35)',
  borderColor: '#5e5e5e',
  containerColor: '#242424',
};

function toUnderline(name: string): string {
  return name.replace(/([A-Z])/g, '_$1').toUpperCase();
}

export function getBrandColor(type: string, colorList: ColorSeries): ColorToken {
  const name = /^#[A-F\d]{6}$/i.test(type) ? type : toUnderline(type);
  return colorList[name || 'DEFAULT'];
}

export function getColorList(colorArray: Array<ColorToken>): Array<string> {
  const pureColorList = [];
  colorArray.map((colorToken) => Object.keys(colorToken).map((key) => pureColorList.push(colorToken[key])));

  return pureColorList;
}
// inspired by https://stackoverflow.com/questions/36721830/convert-hsl-to-rgb-and-hex
export function hslToHex(h: number, s: number, l: number) {
  l /= 100;
  const a = (s * Math.min(l, 1 - l)) / 100;
  const f = (n: number) => {
    const k = (n + h / 30) % 12;
    const color = l - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
    return Math.round(255 * color)
      .toString(16)
      .padStart(2, '0');
  };
  return `#${f(0)}${f(8)}${f(4)}`;
}

export function generateColorMap(theme: string, colorPalette: Array<string>, mode: 'light' | 'dark') {
  const isDarkMode = mode === 'dark';
  let brandColorIdx = colorPalette.indexOf(theme);

  if (isDarkMode) {
    // eslint-disable-next-line no-use-before-define
    colorPalette.reverse().map((color) => {
      const [h, s, l] = Color.colorTransform(color, 'hex', 'hsl');
      return Color.colorTransform([h, Number(s) - 4, l], 'hsl', 'hex');
    });
    brandColorIdx = 5;
    colorPalette[0] = `${colorPalette[brandColorIdx]}20`;
  }

  const colorMap = {
    '--td-brand-color': colorPalette[brandColorIdx], // 主题色
    '--td-brand-color-1': colorPalette[0], // light
    '--td-brand-color-2': colorPalette[1], // focus
    '--td-brand-color-3': colorPalette[2], // disabled
    '--td-brand-color-4': colorPalette[3],
    '--td-brand-color-5': colorPalette[4],
    '--td-brand-color-6': colorPalette[5],
    '--td-brand-color-7': brandColorIdx > 0 ? colorPalette[brandColorIdx - 1] : theme, // hover
    '--td-brand-color-8': colorPalette[brandColorIdx], // 主题色
    '--td-brand-color-9': brandColorIdx > 8 ? theme : colorPalette[brandColorIdx + 1], // click
    '--td-brand-color-10': colorPalette[9],
  };
  return colorMap;
}
export function insertThemeStylesheet(theme: string, colorMap: ColorToken, mode: 'light' | 'dark') {
  const isDarkMode = mode === 'dark';
  const root = !isDarkMode ? `:root[theme-color='${theme}']` : `:root[theme-color='${theme}'][theme-mode='dark']`;

  const styleSheet = document.createElement('style');
  styleSheet.type = 'text/css';
  styleSheet.innerText = `${root}{
    --td-brand-color: ${colorMap['--td-brand-color']};
    --td-brand-color-1: ${colorMap['--td-brand-color-1']};
    --td-brand-color-2: ${colorMap['--td-brand-color-2']};
    --td-brand-color-3: ${colorMap['--td-brand-color-3']};
    --td-brand-color-4: ${colorMap['--td-brand-color-4']};
    --td-brand-color-5: ${colorMap['--td-brand-color-5']};
    --td-brand-color-6: ${colorMap['--td-brand-color-6']};
    --td-brand-color-7: ${colorMap['--td-brand-color-7']};
    --td-brand-color-8: ${colorMap['--td-brand-color-8']};
    --td-brand-color-9: ${colorMap['--td-brand-color-9']};
    --td-brand-color-10: ${colorMap['--td-brand-color-10']};
  }`;

  document.head.appendChild(styleSheet);
}
