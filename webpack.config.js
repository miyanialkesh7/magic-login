const config = require('10up-toolkit/config/webpack.config');

const withoutWebpackBar = (webpackConfig) => ({
	...webpackConfig,
	plugins: webpackConfig.plugins.filter(
		(plugin) => plugin?.constructor?.name !== 'WebpackBarPlugin'
	),
});

module.exports = Array.isArray(config)
	? config.map(withoutWebpackBar)
	: withoutWebpackBar(config);
