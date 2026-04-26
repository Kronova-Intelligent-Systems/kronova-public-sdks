// Bypass missing type definitions for raw crypto libraries
declare module 'dilithium-crystals-js' {
    const content: any;
    export = content;
}

declare module 'crystals-kyber' {
    const content: any;
    export = content;
}

declare module 'crystals-dilithium' {
    const content: any;
    export = content;
}