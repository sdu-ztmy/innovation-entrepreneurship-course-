import cv2
import numpy as np
from scipy.fftpack import dct, idct
from skimage import util, exposure
import matplotlib.pyplot as plt

class DigitalWatermark:
    def __init__(self, alpha=0.1, block_size=8, frequency_band=(5,5)):
        self.alpha = alpha
        self.block_size = block_size
        self.frequency_band = frequency_band
    
    def _pad_image_to_block_size(self, img):
        h, w = img.shape[:2]
        pad_h = (self.block_size - h % self.block_size) % self.block_size
        pad_w = (self.block_size - w % self.block_size) % self.block_size
        
        if len(img.shape) == 3:
            return cv2.copyMakeBorder(img, 0, pad_h, 0, pad_w, cv2.BORDER_REFLECT)
        else:
            return cv2.copyMakeBorder(img, 0, pad_h, 0, pad_w, cv2.BORDER_REFLECT)
    
    def _process_image_channels(self, img):
        img_padded = self._pad_image_to_block_size(img)
        yuv_img = cv2.cvtColor(img_padded, cv2.COLOR_BGR2YCrCb)
        y, u, v = cv2.split(yuv_img)
        return y.astype(float), u, v, img.shape[:2]
    
    def _reconstruct_image(self, y_channel, u, v, original_shape):
        y_channel = y_channel[:original_shape[0], :original_shape[1]]
        u = u[:original_shape[0], :original_shape[1]]
        v = v[:original_shape[0], :original_shape[1]]
        yuv_img = cv2.merge([y_channel.astype(np.uint8), u, v])
        return cv2.cvtColor(yuv_img, cv2.COLOR_YCrCb2BGR)
    
    def _get_image_blocks(self, channel):
        h, w = channel.shape
        blocks = []
        for j in range(0, h, self.block_size):
            for i in range(0, w, self.block_size):
                block = channel[j:j+self.block_size, i:i+self.block_size]
                if block.shape == (self.block_size, self.block_size):
                    blocks.append(block)
        return blocks
    
    def _reconstruct_channel(self, blocks, original_shape):
        h, w = original_shape
        pad_h = (self.block_size - h % self.block_size) % self.block_size
        pad_w = (self.block_size - w % self.block_size) % self.block_size
        padded_h = h + pad_h
        padded_w = w + pad_w
        
        channel = np.zeros((padded_h, padded_w))
        block_idx = 0
        for j in range(0, padded_h, self.block_size):
            for i in range(0, padded_w, self.block_size):
                if block_idx < len(blocks):
                    block = blocks[block_idx]
                    if block.shape == (self.block_size, self.block_size):
                        channel[j:j+self.block_size, i:i+self.block_size] = block
                    block_idx += 1
        return channel
    
    def string_to_bits(self, s):
        return [int(bit) for char in s for bit in format(ord(char), '08b')]
    
    def bits_to_string(self, bits):
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(''.join(map(str, byte)), 2)))
        return ''.join(chars)
    
    def embed_watermark(self, original_img, watermark_data, is_string=True):
        if is_string:
            watermark = self.string_to_bits(watermark_data)
        else:
            watermark = watermark_data
        
        y_channel, u, v, original_shape = self._process_image_channels(original_img)
        blocks = self._get_image_blocks(y_channel)
        
        max_watermark_length = len(blocks)
        if len(watermark) > max_watermark_length:
            raise ValueError(f"水印过长，最大支持{max_watermark_length}位")
        
        watermarked_blocks = []
        watermark_idx = 0
        for block in blocks:
            if watermark_idx < len(watermark):
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                coeff = dct_block[self.frequency_band]
                if watermark[watermark_idx] == 1:
                    dct_block[self.frequency_band] = coeff * (1 + self.alpha)
                else:
                    dct_block[self.frequency_band] = coeff * (1 - self.alpha)
                modified_block = idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
                watermarked_blocks.append(modified_block)
                watermark_idx += 1
            else:
                watermarked_blocks.append(block)
        
        watermarked_y = self._reconstruct_channel(watermarked_blocks, original_shape)
        return self._reconstruct_image(watermarked_y, u, v, original_shape)
    
    def extract_watermark(self, watermarked_img, original_img, watermark_length=None, is_string=True):
        wm_y, wm_u, wm_v, original_shape = self._process_image_channels(watermarked_img)
        orig_y, _, _, _ = self._process_image_channels(original_img)
        
        wm_blocks = self._get_image_blocks(wm_y)
        orig_blocks = self._get_image_blocks(orig_y)
        
        if watermark_length is None:
            watermark_length = len(wm_blocks)
        
        extracted_bits = []
        for i in range(min(watermark_length, len(wm_blocks), len(orig_blocks))):
            wm_dct = dct(dct(wm_blocks[i].T, norm='ortho').T, norm='ortho')
            orig_dct = dct(dct(orig_blocks[i].T, norm='ortho').T, norm='ortho')
            wm_coeff = wm_dct[self.frequency_band]
            orig_coeff = orig_dct[self.frequency_band]
            if wm_coeff > orig_coeff:
                extracted_bits.append(1)
            else:
                extracted_bits.append(0)
        
        if is_string:
            return self.bits_to_string(extracted_bits)
        else:
            return extracted_bits
    
    def apply_attack(self, img, attack_type):
        if attack_type == 'flip':
            return cv2.flip(img, -1)  
            
        elif attack_type == 'translation':
            rows, cols = img.shape[:2]
            M = np.float32([[1,0,20],[0,1,15]])
            return cv2.warpAffine(img, M, (cols, rows))
            
        elif attack_type == 'cropping':
            rows, cols = img.shape[:2]
            crop_size = int(min(rows, cols)*0.25)
            return img[crop_size:rows-crop_size, crop_size:cols-crop_size]
            
        elif attack_type == 'contrast':
            return exposure.adjust_gamma(img, gamma=0.3)
            
        elif attack_type == 'noise':
            noisy = util.random_noise(img, mode='gaussian', var=0.05)
            return (255*noisy).astype(np.uint8)
            
        elif attack_type == 'jpeg':
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 30]
            _, encimg = cv2.imencode('.jpg', img, encode_param)
            return cv2.imdecode(encimg, 1)
            
        else:
            return img.copy()

    def visualize_results(self, original_img, watermarked_img, robustness_results, attacked_images, watermark_data):
        attacks = ['flip', 'translation', 'cropping', 'contrast', 'noise', 'jpeg']
        
        plt.figure(figsize=(18, 12))

        plt.subplot(3, 4, 1)
        plt.imshow(cv2.cvtColor(original_img, cv2.COLOR_BGR2RGB))
        plt.title("Original Image\n(Reference)")
        plt.axis('off')
        
        plt.subplot(3, 4, 2)
        plt.imshow(cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2RGB))
        plt.title("Watermarked Image\n(Baseline)")
        plt.axis('off')
 
        mse = np.mean((original_img - watermarked_img) ** 2)
        psnr = 20 * np.log10(255.0 / np.sqrt(mse)) if mse != 0 else 100

        plt.subplot(3, 4, 3)
        text = f"Embedded Watermark:\n{watermark_data}\n\n"
        text += f"PSNR: {psnr:.2f} dB\n"
        text += "Extraction Accuracy:\n"
        for attack in attacks:
            text += f"{attack:12s}: {robustness_results[attack]*100:5.1f}%\n"
        plt.text(0.1, 0.5, text, fontsize=11, family='monospace')
        plt.axis('off')

        attack_titles = {
            'flip': "Flipped\n(H+V Flip)",
            'translation': "Translated\n(20px,15px)",
            'cropping': "Cropped\n(25% removed)",
            'contrast': "Contrast\n(Gamma=0.3)",
            'noise': "Noisy\n(Var=0.05)",
            'jpeg': "JPEG\n(Quality=30)"
        }
        
        for i, attack in enumerate(attacks):
            plt.subplot(3, 4, i+5)
            plt.imshow(cv2.cvtColor(attacked_images[attack], cv2.COLOR_BGR2RGB))
            plt.title(f"{attack_titles[attack]}\nAcc: {robustness_results[attack]*100:.1f}%")
            plt.axis('off')
        
        plt.tight_layout()
        output_path = "watermark_robustness_results.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Visualization saved to: {output_path}")
        
        plt.show()
        plt.close()

    def save_attacked_images(self, attacked_images):
        for attack, img in attacked_images.items():
            filename = f"attacked_{attack}.jpg"
            cv2.imwrite(filename, cv2.cvtColor(img, cv2.COLOR_RGB2BGR))
            print(f"Saved {attack} image: {filename}")
    
    def test_robustness(self, watermarked_img, original_img, watermark_data, is_string=True):
        if is_string:
            original_bits = self.string_to_bits(watermark_data)
        else:
            original_bits = watermark_data
        
        attacks = ['flip', 'translation', 'cropping', 'contrast', 'noise', 'jpeg']
        results = {}
        attacked_images = {}
        
        for attack in attacks:
            # 应用独立攻击
            attacked_img = self.apply_attack(watermarked_img, attack)
            
            # 对于裁剪攻击，需要同样裁剪原始图像
            if attack == 'cropping':
                orig_attacked = self.apply_attack(original_img, attack)
            else:
                orig_attacked = original_img
            
            # 提取水印
            extracted = self.extract_watermark(attacked_img, orig_attacked, 
                                             len(original_bits), False)
            accuracy = np.mean(np.array(extracted) == np.array(original_bits))
            
            results[attack] = accuracy
            attacked_images[attack] = attacked_img
        
        return results, attacked_images

    

def main():
    # 1. 加载图像
    original_img = cv2.imread("test.jpg")
    if original_img is None:
        print("错误：无法加载图像，请确保'test.jpg'存在")
        return
    
    # 2. 创建水印系统实例
    watermark_system = DigitalWatermark(alpha=0.3)
    
    # 3. 嵌入水印
    watermark_data = "Copyright2023"
    watermarked_img = watermark_system.embed_watermark(original_img, watermark_data)
    cv2.imwrite("watermarked_image.jpg", watermarked_img)
    
    # 4. 提取原始水印
    extracted_watermark = watermark_system.extract_watermark(
        watermarked_img, original_img, 
        watermark_length=None,
        is_string=True
    )
    print(f"提取的水印: {extracted_watermark}")
    
    # 5. 测试鲁棒性（每种攻击独立进行）
    robustness_results, attacked_images = watermark_system.test_robustness(
        watermarked_img, original_img, watermark_data
    )
    
    # 6. 可视化结果
    watermark_system.visualize_results(
        original_img, watermarked_img, 
        robustness_results, attacked_images,
        watermark_data
    )


if __name__ == "__main__":
    main()