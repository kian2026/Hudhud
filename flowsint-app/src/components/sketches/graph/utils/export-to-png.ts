export const exportToPNG = async (canvaId: string, sketchId: string) => {
    // Find the ForceGraph2D canvas element
    // The library renders a <canvas> inside a container — we search for it dynamically
    const canvas =
        (canvaId && canvaId !== 'null' && document.getElementById(canvaId) as HTMLCanvasElement) ||
        document.querySelector('.force-graph-container canvas') as HTMLCanvasElement ||
        document.querySelector('canvas') as HTMLCanvasElement

    if (!canvas) {
        throw new Error('Canvas element not found. Make sure the graph is rendered.')
    }

    return new Promise<void>((resolve, reject) => {
        canvas.toBlob((blob) => {
            if (!blob) {
                reject(new Error('Failed to create image blob'))
                return
            }
            // Create download link
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `sketch-${sketchId || 'export'}-${Date.now()}.png`
            document.body.appendChild(a)
            a.click()
            // Cleanup
            URL.revokeObjectURL(url)
            document.body.removeChild(a)
            resolve()
        }, 'image/png')
    })
}