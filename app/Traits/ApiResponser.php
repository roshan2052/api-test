<?php

namespace App\Traits;

trait ApiResponser{

    protected function successResponse($data, $message = null, $code = 200)
    {
		return response()->json([
			'success'   => true,
			'data'      => $data,
			'message'   => $message,
		], $code);
	}

	protected function errorResponse($message = null, $code = 500)
	{
		return response()->json([
			'success'   => false,
			'message'   => $message,
		], $code);
	}

}
