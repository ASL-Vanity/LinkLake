(() => {
        try {
          const root = document.documentElement;
          const mode = localStorage.getItem('linklake-theme-mode') || 'system';
          const palette = localStorage.getItem('linklake-palette') || 'lake';
          const systemDark = matchMedia('(prefers-color-scheme: dark)').matches;
          root.dataset.themeMode = ['system', 'light', 'dark'].includes(mode) ? mode : 'system';
          root.dataset.scheme = mode === 'system' ? (systemDark ? 'dark' : 'light') : mode;
          root.dataset.palette = ['lake', 'ocean', 'jade', 'violet', 'contrast'].includes(palette) ? palette : 'lake';
        } catch (_) {}
      })();
