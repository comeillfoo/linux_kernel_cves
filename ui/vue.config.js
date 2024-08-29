module.exports = {
  publicPath: process.env.NODE_ENV === "production" ? "/linux_kernel_cves/" : "/",
  configureWebpack:{
    performance: {
      hints: false
    },
    optimization: {
      splitChunks: {
        minSize: 10000,
        maxSize: 250000,
      }
    }
  }
}