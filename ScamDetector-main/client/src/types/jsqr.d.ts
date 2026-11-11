declare module "jsqr" {
  type QRCode = {
    data: string;
    location: unknown;
  };

  export default function jsQR(
    data: Uint8ClampedArray,
    width: number,
    height: number
  ): QRCode | null;
}
