<?php

namespace OhMyBrew\ShopifyApp\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Config;
use OhMyBrew\ShopifyApp\Facades\ShopifyApp;

/**
 * Response for ensuring a proper webhook request.
 */
class AuthWebhook
{
    /**
     * Handle an incoming request to ensure webhook is valid.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure                 $next
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $hmac = $request->header('x-shopify-hmac-sha256') ?: '';
        $shop = $request->header('x-shopify-shop-domain');
        $data = $request->getContent();

        $hmacLocal = ShopifyApp::createHmac(['data' => $data, 'raw' => true, 'encode' => true]);
        if (!hash_equals($hmac, $hmacLocal) || empty($shop)) {

            // Issue with HMAC or missing shop header
            return Response::make('Invalid webhook signature.', 401);
        }

        $valid_shop = $this->validateShop($request);
        if (!$valid_shop) {
            return Response::make('Invalid shop.', 401);
        }

        // All good, process webhook
        return $next($request);
    }

    /**
     * Checks we have a valid shop.
     *
     * @param \Illuminate\Http\Request $request The request object.
     *
     * @return bool
     */
    protected function validateShop(Request $request)
    {

        $shopDomain = $request->header('x-shopify-shop-domain');

        // Get the shop based on domain
        $shopModel = Config::get('shopify-app.shop_model');
        $shop = $shopModel::where(['shopify_domain' => $shopDomain])->first();

        if (!$shop) {
            return false;
        }
        return true;
    }

}
