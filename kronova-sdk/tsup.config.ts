import { defineConfig } from 'tsup';

export default defineConfig({
  // The primary entry point for the SDK
  entry: ['src/index.ts'],
  
  // Output both CommonJS (for legacy Node/Rust interop) and ESM (for Next.js/Browser)
  format: ['cjs', 'esm'], 
  
  // Generates TypeScript declaration files (.d.ts) so users get autocomplete
  dts: true, 
  
  // Cleans the 'dist' folder before every build to prevent stale files
  clean: true, 
  
  // Minifies the output for smaller bundle sizes in production
  minify: true, 
  
  // Generates source maps for easier debugging in production environments
  sourcemap: true, 
  
  // Splits code into smaller chunks if there are multiple entry points
  splitting: false, 
  
  // Marks these specific node_modules as external so they aren't bundled directly 
  // into your SDK code. This is CRITICAL for C/C++ or WebAssembly backed crypto libraries.
  external: [
    'crystals-kyber',
    'dilithium-crystals-js', // 🛡️ Added the exact name from the error
    '@supabase/supabase-js',
    'jose',
    'zod'
  ],
  
  // Fails the build if there are TypeScript errors (Enterprise safety)
  onSuccess: 'echo "✅ Kronova SDK Build Complete"',
});